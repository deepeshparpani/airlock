use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub fn get_port_file_path() -> PathBuf {
    let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
    env::temp_dir().join(format!("airlock_daemon_{}.port", user))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortManifest {
    pub port: u16,
    pub token: String,
}

impl PortManifest {
    pub fn new(port: u16, token: String) -> Self {
        Self { port, token }
    }

    /// Atomically writes the port and token to disk using a PID-tagged temp file
    /// and atomic rename (POSIX rename(2)) to eliminate race conditions during concurrent client reads.
    pub fn write_atomic(&self) -> std::io::Result<()> {
        let final_path = get_port_file_path();
        let pid = std::process::id();
        let tmp_path = final_path.with_extension(format!("{}.tmp", pid));

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);

        let mut file = options.open(&tmp_path)?;
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = file.set_permissions(perms);
        }

        let content = format!("{}:{}\n", self.port, self.token);
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);

        // Atomic rename eliminates read/write race conditions
        fs::rename(&tmp_path, &final_path)?;

        Ok(())
    }

    /// Safely reads and validates the port and token from the manifest.
    pub fn read_current() -> Option<Self> {
        let path = get_port_file_path();
        if !path.exists() {
            return None;
        }

        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut content = String::new();
        if file.read_to_string(&mut content).is_err() {
            return None;
        }

        let trimmed = content.trim();
        if let Some((port_str, token)) = trimmed.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if !token.is_empty() {
                    return Some(PortManifest {
                        port,
                        token: token.to_string(),
                    });
                }
            }
        }

        None
    }

    pub fn remove_current() {
        let path = get_port_file_path();
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_port_manifest_roundtrip() {
        let manifest = PortManifest::new(54321, "abc123secret".to_string());
        manifest.write_atomic().expect("Atomic write must succeed");

        let loaded = PortManifest::read_current().expect("Read must succeed");
        assert_eq!(loaded.port, 54321);
        assert_eq!(loaded.token, "abc123secret");

        PortManifest::remove_current();
        assert!(PortManifest::read_current().is_none());
    }
}
