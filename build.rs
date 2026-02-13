use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Tell Cargo to rerun this build script if Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Read Cargo.toml
    let cargo_toml_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");
    let cargo_toml_content = match fs::read_to_string(&cargo_toml_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Warning: Could not read Cargo.toml: {}", e);
            return;
        }
    };

    // Parse application_version from [workspace.metadata.ci-tools]
    let application_version =
        extract_application_version(&cargo_toml_content).unwrap_or_else(|| {
            eprintln!("Warning: Could not find application_version in Cargo.toml, using 'unknown'");
            "unknown".to_string()
        });

    println!(
        "cargo:rustc-env=APPLICATION_VERSION={}",
        application_version
    );
}

fn extract_application_version(content: &str) -> Option<String> {
    let mut in_ci_tools_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Check if we're entering the ci-tools section
        if trimmed.starts_with("[workspace.metadata.ci-tools]") {
            in_ci_tools_section = true;
            continue;
        }

        // If we hit another section, stop looking
        if trimmed.starts_with('[') && !trimmed.starts_with("[workspace.metadata.ci-tools]") {
            in_ci_tools_section = false;
            continue;
        }

        // Look for application_version in the ci-tools section
        if in_ci_tools_section && trimmed.starts_with("application_version") {
            // Extract value between quotes
            if let Some(start) = trimmed.find('"') {
                let start = start + 1;
                if let Some(end) = trimmed[start..].find('"') {
                    return Some(trimmed[start..start + end].to_string());
                }
            }
        }
    }

    None
}
