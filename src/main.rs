use chrono::DateTime;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs,
    io::{BufReader, Error as IoError, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{atomic, Arc},
    time::SystemTime,
};
use zip::result::ZipError;

const ZSTD_COMPRESSION_LEVEL: i64 = 7;
const PROGRESSBAR_TEMPLATE: &str =
    "{msg:<30} | [{elapsed_precise:^8}] | {bytes:>11}/{total_bytes:<11} | ~{eta:^6} | [{wide_bar}]";
const PROGRESSBAR_BAR_CHARACTERS: &str = "=>-";

#[derive(Parser, Debug)]
#[command(version, about, author, long_about = None)]
struct CommandLineOptions {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Archive + Encrypt + Compress files of an input directory (only first level of files)
    Archive {
        /// Directory path to archive
        #[arg()]
        directory: String,
        /// Zstd compression level (between -7 - 22)
        #[arg(short, value_parser = zstd_compression_level_parser, default_value_t = ZSTD_COMPRESSION_LEVEL)]
        zstd_compression_level: i64,
        /// Compression method.
        #[arg(long, value_enum, default_value_t = CompressionMethod::Zstd)]
        compression_method: CompressionMethod,
    },
    /// Extract + Decrypt + Decompress contents of an archive file
    Extract {
        /// Archived .pcrypt.zip file path to extract
        #[arg()]
        archived_file: String,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CompressionMethod {
    /// Fast and efficeint but (for now) you have to decompress archives only using this app.
    Zstd,
    /// VERY SLOW (compared to `zstd`), but you can decompress archive via well-known tools like 7z.
    Bzip2,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Directory {directory:?} does not exists")]
    DirectoryNotFound { directory: PathBuf },
    #[error("Compressed file {filename:?} does not exists")]
    ArchivedFileNotFound { filename: PathBuf },
    #[error("{directory:?} is not a valid directory")]
    NotADirectory { directory: PathBuf },
    #[error("{filename:?} is not a regular file")]
    NotAFile { filename: PathBuf },
    #[error("{filename:?} is not archived via this application")]
    NotArchivedByMe { filename: PathBuf },
    #[error("Could not search inside directory {directory:?}")]
    SearchDirectory { directory: PathBuf, source: IoError },
    #[error("{filename:?} is not a valid zip archive")]
    NotAZip { filename: PathBuf, source: ZipError },
    #[error("There is no file to archive inside {directory:?}")]
    NothingToArchive { directory: PathBuf },
    #[error("There is no file to extract inside {filename:?}")]
    NothingToDeExtract { filename: PathBuf },
    #[error("Could not normalize path {path:?}")]
    NormalizePath { path: PathBuf, source: IoError },
    #[error("Archive file {filename:?} already exists")]
    FileAlreadyExists { filename: PathBuf },
    #[error("Could not detect directory name from {directory:?}")]
    DetectDirectoryName { directory: PathBuf },
    #[error("Could not create file {filename:?}")]
    CreateFile { filename: PathBuf, source: IoError },
    #[error("Could not create zip file")]
    ZipArchive { source: ZipError },
    #[error("Could not read file {filename:?}")]
    ReadFile { filename: PathBuf, source: IoError },
    #[error("Could not write into file {filename:?}")]
    WriteFile { filename: PathBuf, source: IoError },
    #[error("Could not write to zip file")]
    ZipWrite { source: IoError },
    #[error("Could not read archive file {filename:?} from zip archive")]
    ZipRead { filename: PathBuf, source: ZipError },
    #[error("Stopped")]
    Stopped,
    #[error("Could not read user password from input")]
    ReadPassword { source: IoError },
}

fn main() -> anyhow::Result<()> {
    let commandline_options = CommandLineOptions::parse();
    let running = Arc::new(atomic::AtomicBool::new(true));
    let ctrlc_running = running.clone();
    if let Err(error) = ctrlc::set_handler(move || {
        ctrlc_running.store(false, atomic::Ordering::SeqCst);
    }) {
        eprintln!("Could not setup Ctrl-C handler: {error}")
    };
    #[cfg(not(feature = "password-from-env"))]
    let password_func = || -> Result<String> {
        rpassword::prompt_password("Enter Password: ")
            .map_err(|error| Error::ReadPassword { source: error })
    };
    // For test environment:
    #[cfg(feature = "password-from-env")]
    let password_func = || -> Result<String> {
        std::env::var("PCRYPT_PASSWORD").map_err(|error| Error::ReadPassword {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, error),
        })
    };
    match commandline_options.command {
        Commands::Archive {
            directory,
            zstd_compression_level,
            compression_method,
        } => archive(
            directory,
            zstd_compression_level,
            compression_method,
            running.clone(),
            password_func,
        ),
        Commands::Extract { archived_file } => {
            extract(archived_file, running.clone(), password_func)
        }
    }
    .map_err(|error| anyhow::anyhow!(error))
}

fn zstd_compression_level_parser(v: &str) -> std::result::Result<i64, String> {
    v.parse()
        .map_err(|_| format!("could not convert {v:?} to number"))
        .and_then(|n| {
            if !(-7..=22).contains(&n) {
                Err("Zstd compression level MUST be between -7 - 22".into())
            } else {
                Ok(n)
            }
        })
}

#[inline(always)]
fn is_running(running: &Arc<atomic::AtomicBool>) -> Result<()> {
    if running.load(atomic::Ordering::Relaxed) {
        Ok(())
    } else {
        Err(Error::Stopped)
    }
}

#[inline(always)]
fn reduce_to_30_characters<P: AsRef<Path>>(x: P) -> String {
    let x = x.as_ref().to_str().unwrap_or_default().to_string();
    let character_count = x.chars().count();
    if character_count > 30 {
        return format!(
            "{}...{}",
            x.chars().take(13).collect::<String>(),
            x.chars().skip(character_count - 13).collect::<String>()
        );
    };
    x
}

fn archive<D: AsRef<Path>>(
    directory: D,
    zstd_compression_level: i64,
    compression_method: CompressionMethod,
    running: Arc<atomic::AtomicBool>,
    read_password: impl Fn() -> Result<String>,
) -> Result<()> {
    let directory = directory.as_ref();
    let directory = directory
        .canonicalize()
        .map_err(|error| Error::NormalizePath {
            path: directory.to_path_buf(),
            source: error,
        })?;
    let directory_name = if let Some(directory_name) = directory.file_name() {
        if let Some(directory_name) = directory_name.to_str() {
            directory_name.to_string()
        } else {
            return Err(Error::DetectDirectoryName { directory });
        }
    } else {
        return Err(Error::DetectDirectoryName { directory });
    };
    is_running(&running)?;

    if !directory.exists() {
        return Err(Error::DirectoryNotFound {
            directory: directory.clone(),
        });
    };
    if !directory.is_dir() {
        return Err(Error::NotADirectory {
            directory: directory.clone(),
        });
    };
    is_running(&running)?;

    let file_list: Vec<_> = directory
        .read_dir()
        .map_err(|error| Error::SearchDirectory {
            directory: directory.clone(),
            source: error,
        })?
        .filter_map(|entry_result| {
            if let Err(error) = entry_result {
                eprintln!("could not detect directory entry: {error}");
                None
            } else {
                entry_result.ok()
            }
        })
        .map(|entry| entry.path())
        .filter_map(|path| {
            if path.is_file() {
                Some(path)
            } else if path.is_dir() {
                eprintln!("skip archiving directory {path:?}");
                None
            } else {
                eprintln!("skip archiving unhandled file {path:?}");
                None
            }
        })
        .filter_map(|filepath| {
            if filepath.ends_with(".pcrypt.zip") {
                eprintln!("skipping already archivied PCrypt file {filepath:?}");
                None
            } else {
                Some(filepath)
            }
        })
        .filter_map(|filepath| {
            if let Some(filename) = filepath.file_name() {
                if let Some(filename) = filename.to_str() {
                    let filename = filename.to_string();
                    Some((filepath, filename))
                } else {
                    eprintln!("Could not convert filename {filepath:?} to string");
                    None
                }
            } else {
                eprintln!("Could not detect filename in {filepath:?}");
                None
            }
        })
        .collect();
    if file_list.is_empty() {
        return Err(Error::NothingToArchive {
            directory: directory.clone(),
        });
    }
    let time = SystemTime::now();
    let utc_datetime: DateTime<chrono::Utc> = time.into();
    let utc_datetime_string = format!("{}", utc_datetime.format("%Y-%m-%d-%H-%M-%S-%b-%a"));
    let pcrypt_filename = PathBuf::from(format!(
        "{directory_name}-{utc_datetime_string}-{}.pcrypt.zip",
        file_list.len()
    ));
    is_running(&running)?;
    let password = read_password()?;
    println!(
        "Attempt to Archive + Encrypt + Compress {} file(s) into {pcrypt_filename:?}",
        file_list.len()
    );

    let pcrypt_file = fs::File::create(&pcrypt_filename).map_err(|error| Error::CreateFile {
        filename: pcrypt_filename.clone(),
        source: error,
    })?;
    let mut zip = zip::ZipWriter::new(pcrypt_file);
    let (compression_method, compression_level) = match compression_method {
        CompressionMethod::Zstd => (zip::CompressionMethod::Zstd, zstd_compression_level),
        CompressionMethod::Bzip2 => (zip::CompressionMethod::Bzip2, 3),
    };
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(compression_method)
        .compression_level(Some(compression_level))
        .large_file(true)
        .with_aes_encryption(zip::AesMode::Aes256, &password)
        .unix_permissions(0o664);
    is_running(&running).inspect_err(|_| {
        let _ = zip.abort_file();
        let _ = fs::remove_file(&pcrypt_filename);
    })?;

    let multi_progress_bar = indicatif::MultiProgress::new();
    file_list
        .into_iter()
        .try_for_each(|(filepath, filename)| {
            zip.start_file(&filename, options)
                .map_err(|error| Error::ZipArchive { source: error })?;
            let mut file = fs::OpenOptions::new()
                .read(true)
                .open(&filepath)
                .map_err(|error| Error::ReadFile {
                    filename: filepath.clone(),
                    source: error,
                })?;
            is_running(&running)?;

            let file_size = file
                .metadata()
                .map(|metadata| metadata.size())
                .unwrap_or_default();
            let progress_bar = indicatif::ProgressBar::new(file_size)
                .with_message(reduce_to_30_characters(filename));
            progress_bar.set_style(
                indicatif::ProgressStyle::with_template(PROGRESSBAR_TEMPLATE)
                    .unwrap()
                    .progress_chars(PROGRESSBAR_BAR_CHARACTERS),
            );
            let progress_bar = multi_progress_bar.add(progress_bar);
            let mut buffer: [u8; 1048576] = [0; 1048576];
            is_running(&running)?;

            loop {
                let bytes_read = file.read(&mut buffer).map_err(|error| Error::ReadFile {
                    filename: filepath.clone(),
                    source: error,
                })?;
                progress_bar.inc(bytes_read as u64);
                if bytes_read == 0 {
                    progress_bar.finish();
                    break;
                }
                zip.write_all(&buffer[0..bytes_read])
                    .map_err(|error| Error::ZipWrite { source: error })?;
                is_running(&running)?;
            }
            Ok(())
        })
        .inspect_err(|_| {
            let _ = zip.abort_file();
            let _ = fs::remove_file(&pcrypt_filename);
        })?;
    zip.finish().map_err(|error| {
        let _ = fs::remove_file(&pcrypt_filename);
        Error::ZipArchive { source: error }
    })?;
    Ok(())
}

fn extract<F: AsRef<Path>>(
    archived_filename: F,
    running: Arc<atomic::AtomicBool>,
    read_password: impl Fn() -> Result<String>,
) -> Result<()> {
    let archived_filename = archived_filename.as_ref();
    let archived_filename =
        archived_filename
            .canonicalize()
            .map_err(|error| Error::NormalizePath {
                path: archived_filename.to_path_buf(),
                source: error,
            })?;
    is_running(&running)?;

    if !archived_filename.exists() {
        return Err(Error::ArchivedFileNotFound {
            filename: archived_filename.clone(),
        });
    };
    if !archived_filename.is_file() {
        return Err(Error::NotAFile {
            filename: archived_filename.to_path_buf(),
        });
    };
    if archived_filename.ends_with(".pcrypt.zip") {
        return Err(Error::NotArchivedByMe {
            filename: archived_filename.clone(),
        });
    }
    is_running(&running)?;

    let archived_file = fs::File::open(&archived_filename).map_err(|error| Error::ReadFile {
        filename: archived_filename.clone(),
        source: error,
    })?;
    let reader = BufReader::new(archived_file);
    let mut archive = zip::ZipArchive::new(reader).map_err(|error| Error::NotAZip {
        filename: archived_filename.clone(),
        source: error,
    })?;
    if archive.is_empty() {
        return Err(Error::NothingToDeExtract {
            filename: archived_filename.clone(),
        });
    };
    is_running(&running)?;
    (0..archive.len()).try_for_each(|index| {
        let archive_file = archive.by_index_raw(index).unwrap();
        let archive_filename = archive_file.mangled_name();
        if archive_filename.exists() {
            return Err(Error::FileAlreadyExists {
                filename: archive_filename,
            });
        };
        Ok(())
    })?;
    is_running(&running)?;
    let password = read_password()?;
    println!(
        "Attempt to Extract + Decrypt + Decompress {} files from {archived_filename:?}",
        archive.len()
    );

    let multi_progress_bar = indicatif::MultiProgress::new();
    let mut file_list = Vec::with_capacity(archive.len());
    (0..archive.len())
        .try_for_each(|index| {
            let archive_filename = archive.by_index_raw(index).unwrap().mangled_name();
            let mut archive_file = archive
                .by_index_decrypt(index, password.as_bytes())
                .map_err(|error| Error::ZipRead {
                    filename: archive_filename.clone(),
                    source: error,
                })?;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&archive_filename)
                .map_err(|error| Error::CreateFile {
                    filename: archive_filename.clone(),
                    source: error,
                })?;
            file_list.push(archive_filename.clone());
            is_running(&running)?;

            let file_size = archive_file.size();
            let progress_bar = indicatif::ProgressBar::new(file_size)
                .with_message(reduce_to_30_characters(&archive_filename));
            progress_bar.set_style(
                indicatif::ProgressStyle::with_template(PROGRESSBAR_TEMPLATE)
                    .unwrap()
                    .progress_chars(PROGRESSBAR_BAR_CHARACTERS),
            );
            let progress_bar = multi_progress_bar.add(progress_bar);
            let mut buffer: [u8; 1048576] = [0; 1048576];
            is_running(&running)?;
            loop {
                let bytes_read =
                    archive_file
                        .read(&mut buffer)
                        .map_err(|error| Error::ReadFile {
                            filename: archive_filename.clone(),
                            source: error,
                        })?;
                progress_bar.inc(bytes_read as u64);
                if bytes_read == 0 {
                    progress_bar.finish();
                    break;
                }
                file.write_all(&buffer[0..bytes_read])
                    .map_err(|error| Error::WriteFile {
                        filename: archive_filename.clone(),
                        source: error,
                    })?;
                is_running(&running)?;
            }
            Ok(())
        })
        .inspect_err(|_| {
            file_list.into_iter().for_each(|filename| {
                let _ = fs::remove_file(&filename);
                eprintln!("Removed extracted file {filename:?}");
            });
        })?;
    Ok(())
}
