use std::env;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

pub fn get_lock_file_path() -> PathBuf {
    let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
    env::temp_dir().join(format!("airlock_daemon_{}.lock", user))
}

pub struct SingletonLock {
    _file: File,
    path: PathBuf,
    fd: RawFd,
}

impl SingletonLock {
    /// Attempts to acquire an exclusive, non-blocking advisory lock on the daemon lockfile.
    pub fn acquire() -> Option<Self> {
        Self::acquire_at_path(get_lock_file_path())
    }

    /// Attempts to acquire lock at an explicit path.
    pub fn acquire_at_path(path: PathBuf) -> Option<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).mode(0o600);

        let file = options.open(&path).ok()?;

        // Explicitly set 0600 permissions
        if let Ok(metadata) = file.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = file.set_permissions(perms);
        }

        let fd = file.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

        if ret != 0 {
            // Lock is held by another process
            return None;
        }

        Some(SingletonLock {
            _file: file,
            path,
            fd,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SingletonLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_singleton_lock_mutual_exclusion() {
        let test_lock_path = env::temp_dir().join(format!("airlock_test_{}.lock", std::process::id()));

        let lock1 = SingletonLock::acquire_at_path(test_lock_path.clone());
        assert!(lock1.is_some(), "First lock acquisition should succeed");

        let lock2 = SingletonLock::acquire_at_path(test_lock_path.clone());
        assert!(lock2.is_none(), "Second lock acquisition while held must fail (prevent race condition)");

        drop(lock1);

        let lock3 = SingletonLock::acquire_at_path(test_lock_path);
        assert!(lock3.is_some(), "After dropping lock1, lock acquisition should succeed again");
    }
}
