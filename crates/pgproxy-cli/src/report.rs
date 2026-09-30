//! Publish private reports atomically without following destination symlinks.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

struct Pending(PathBuf);
impl Drop for Pending {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn write(path: &Path, report: &serde_json::Value) -> io::Result<()> {
    // Serialize before touching disk so a serialization failure preserves the old report.
    let mut bytes = serde_json::to_vec_pretty(report).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report requires a file path",
        ));
    }
    let temporary = parent.join(format!(".pgproxy-report-{:032x}", rand::random::<u128>()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let pending = Pending(temporary);
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&pending.0, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pgproxy-report-test-{:032x}",
                rand::random::<u128>()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn failed_publication_preserves_destination_and_removes_temporary_file() {
        let directory = Directory::new();
        let path = directory.0.join("occupied");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("existing"), "keep").unwrap();
        assert!(write(&path, &serde_json::json!({"secret": "sample"})).is_err());
        assert_eq!(fs::read_to_string(path.join("existing")).unwrap(), "keep");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn replaces_symlink_without_modifying_target_and_enforces_private_mode() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = Directory::new();
        let target = directory.0.join("target");
        let report = directory.0.join("report");
        fs::write(&target, "preserve").unwrap();
        symlink(&target, &report).unwrap();
        write(&report, &serde_json::json!({"rows": 1})).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "preserve");
        assert!(
            !fs::symlink_metadata(&report)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&report, fs::Permissions::from_mode(0o644)).unwrap();
        write(&report, &serde_json::json!({"rows": 2})).unwrap();
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
