# PCrypt
A utility to Archive (zip) + Encrypt (AES-256) + Compress (Zstd) directory files and vice versa

![pcrypt](https://github.com/user-attachments/assets/140c4ba1-bc08-41f9-8ea2-ee0f9adfbf70)


# Usage
```sh
~ $ pcrypt --help
```
```text
A utility to Archive (zip) + Encrypt (AES-256) + Compress (Zstd) directory files and vice versa

Usage: 

Commands:
  archive  Archive + Encrypt + Compress files of an input directory (only first level of files)
  extract  Extract + Decrypt + Decompress contents of an archive file
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Archive Usage
```sh
~ $ pcrypt archive --help 
```
```text
Archive + Encrypt + Compress files of an input directory (only first level of files)

Usage: 

Arguments:
  <DIRECTORY>
          Directory path to archive

Options:
  -z <ZSTD_COMPRESSION_LEVEL>
          Zstd compression level (between -7 - 22)
          
          [default: 7]

      --compression-method <COMPRESSION_METHOD>
          Compression method
          
          [default: zstd]

          Possible values:
          - zstd:  Fast and efficeint but (for now) you have to decompress archives only using this app
          - bzip2: VERY SLOW (compared to `zstd`), but you can decompress archive via well-known tools like 7z

  -h, --help
          Print help (see a summary with '-h')
```

### Extract Usage
```sh
~ $ pcrypt extract --help
```
```text
Extract + Decrypt + Decompress contents of an archive file

Usage: 

Arguments:
  <ARCHIVED_FILE>  Archived .pcrypt.zip file path to extract

Options:
  -h, --help  Print help
```


# Installation
You need to install Rust toolchain and clone & build the repo for now (or wait for GitHub Actions).