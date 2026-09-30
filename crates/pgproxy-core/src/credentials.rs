//! Operator-configured credential adapters. Subprocesses run directly, never through a shell.
use pgproxy_wire::{
    BackendCredentials, BackendTarget,
    credentials::{CredentialLease, CredentialProvider},
};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_OUTPUT: u64 = 65536;
fn default_ttl() -> u64 {
    300
}
fn default_timeout() -> u64 {
    5
}
fn aws_program() -> PathBuf {
    PathBuf::from("aws")
}
fn vault_program() -> PathBuf {
    PathBuf::from("vault")
}
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialConfig {
    Environment {
        password_variable: String,
        #[serde(default)]
        user_variable: Option<String>,
        #[serde(default = "default_ttl")]
        ttl_secs: u64,
    },
    File {
        path: PathBuf,
    },
    Command {
        program: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    AwsRds {
        region: String,
        #[serde(default = "aws_program")]
        program: PathBuf,
    },
    Vault {
        role_path: String,
        #[serde(default = "vault_program")]
        program: PathBuf,
    },
}
impl std::fmt::Debug for CredentialConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialConfig(<redacted>)")
    }
}
impl CredentialConfig {
    pub fn validate(&self) -> Result<(), String> {
        let valid_name = |name: &str| {
            !name.is_empty()
                && name.len() <= 256
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        };
        match self {
            Self::Environment { password_variable, user_variable, ttl_secs } if !valid_name(password_variable) || user_variable.as_ref().is_some_and(|n| !valid_name(n)) || !(1..=3600).contains(ttl_secs) => Err("invalid credential environment names or TTL".into()),
            Self::File { path } if path.as_os_str().is_empty() => Err("credential file path is empty".into()),
            Self::Command { program, args, timeout_secs } if !program.is_absolute() || !(1..=30).contains(timeout_secs) || args.len()>32 || args.iter().any(|a| a.len()>4096 || a.contains('\0')) => Err("credential command requires an absolute executable, bounded arguments and timeout".into()),
            Self::AwsRds { region, program } if region.is_empty() || region.len()>64 || !region.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'-') || program.as_os_str().is_empty() => Err("invalid AWS RDS credential configuration".into()),
            Self::Vault { role_path, program } if !role_path.contains("/creds/") || role_path.len()>512 || role_path.starts_with('-') || role_path.contains("..") || !role_path.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-/".contains(&b)) || program.as_os_str().is_empty() => Err("invalid Vault dynamic credential path".into()),
            _ => Ok(()),
        }
    }
    pub fn provider(&self) -> io::Result<Arc<dyn CredentialProvider>> {
        self.validate().map_err(io::Error::other)?;
        Ok(Arc::new(Adapter(self.clone())))
    }
}
#[derive(Debug)]
struct Adapter(CredentialConfig);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonLease {
    #[serde(default)]
    user: Option<String>,
    password: String,
    expires_at: u64,
}
fn invalid() -> io::Error {
    io::Error::other("credential provider returned invalid or expired credentials")
}
fn lease(
    template: &BackendCredentials,
    user: Option<String>,
    password: String,
    expires: Instant,
) -> io::Result<CredentialLease> {
    let user = user.unwrap_or_else(|| template.user.clone());
    if user.is_empty()
        || user.len() > 256
        || user.contains('\0')
        || password.is_empty()
        || password.len() > MAX_OUTPUT as usize
        || password.contains('\0')
        || expires <= Instant::now()
    {
        return Err(invalid());
    }
    let mut credentials = template.clone();
    credentials.user = user;
    credentials.password = Some(password);
    Ok(CredentialLease {
        credentials,
        expires_at: Some(expires),
    })
}
fn json_lease(bytes: &[u8], template: &BackendCredentials) -> io::Result<CredentialLease> {
    let value: JsonLease = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid())?;
    let expiry = Duration::from_secs(value.expires_at);
    let remaining = expiry
        .checked_sub(now)
        .filter(|d| !d.is_zero() && *d <= Duration::from_secs(86400))
        .ok_or_else(invalid)?;
    lease(
        template,
        value.user,
        value.password,
        Instant::now() + remaining,
    )
}
impl CredentialProvider for Adapter {
    fn pool_identity(&self) -> String {
        // Per-router provider identity isolates adapter configurations without exposing paths/args.
        format!("provider:{:p}", self)
    }
    fn resolve(
        &self,
        target: &BackendTarget,
        template: &BackendCredentials,
        deadline: Instant,
    ) -> io::Result<CredentialLease> {
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        match &self.0 {
            CredentialConfig::Environment {
                password_variable,
                user_variable,
                ttl_secs,
            } => {
                let password = std::env::var(password_variable).map_err(|_| invalid())?;
                let user = user_variable
                    .as_ref()
                    .map(|key| std::env::var(key).map_err(|_| invalid()))
                    .transpose()?;
                lease(
                    template,
                    user,
                    password,
                    Instant::now() + Duration::from_secs(*ttl_secs),
                )
            }
            CredentialConfig::File { path } => {
                let mut options = OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                let file = options
                    .open(path)
                    .map_err(|_| io::Error::other("credential file unavailable"))?;
                if !file.metadata().map_err(|_| invalid())?.is_file() {
                    return Err(invalid());
                }
                let mut bytes = Vec::new();
                file.take(MAX_OUTPUT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| invalid())?;
                if bytes.len() > MAX_OUTPUT as usize {
                    return Err(invalid());
                }
                json_lease(&bytes, template)
            }
            CredentialConfig::Command {
                program,
                args,
                timeout_secs,
            } => {
                let end = deadline.min(Instant::now() + Duration::from_secs(*timeout_secs));
                let bytes = run(Command::new(program).args(args), end)?;
                json_lease(&bytes, template)
            }
            CredentialConfig::AwsRds { region, program } => {
                let started = Instant::now();
                let bytes = run(
                    Command::new(program).args([
                        "rds",
                        "generate-db-auth-token",
                        "--hostname",
                        &target.host,
                        "--port",
                        &target.port.to_string(),
                        "--username",
                        &template.user,
                        "--region",
                        region,
                    ]),
                    deadline,
                )?;
                aws_lease(bytes, target, template, started)
            }
            CredentialConfig::Vault { role_path, program } => {
                let addr = std::env::var("VAULT_ADDR").map_err(|_| {
                    io::Error::other("Vault requires explicit verified HTTPS configuration")
                })?;
                let insecure = std::env::var("VAULT_SKIP_VERIFY").is_ok_and(|v| {
                    !matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "" | "0" | "false" | "f"
                    )
                });
                if !addr.starts_with("https://") || insecure {
                    return Err(io::Error::other("Vault requires verified HTTPS"));
                }
                let started = Instant::now();
                let bytes = run(
                    Command::new(program).args(["read", "-format=json", role_path]),
                    deadline,
                )?;
                vault_lease(&bytes, template, started)
            }
        }
    }
}
fn aws_lease(
    bytes: Vec<u8>,
    target: &BackendTarget,
    template: &BackendCredentials,
    started: Instant,
) -> io::Result<CredentialLease> {
    let token = String::from_utf8(bytes)
        .map_err(|_| invalid())?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !token.starts_with(&format!("{}:{}/?", target.host, target.port))
        || !token.contains("X-Amz-Signature=")
        || token.contains(['\r', '\n'])
    {
        return Err(invalid());
    }
    // AWS token validity is 15 minutes; conservatively retire authenticated sockets at 14.
    lease(template, None, token, started + Duration::from_secs(840))
}
fn vault_lease(
    bytes: &[u8],
    template: &BackendCredentials,
    started: Instant,
) -> io::Result<CredentialLease> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let ttl = value
        .get("lease_duration")
        .and_then(|v| v.as_u64())
        .filter(|n| (2..=86400).contains(n))
        .ok_or_else(invalid)?;
    let data = value.get("data").ok_or_else(invalid)?;
    let user = data
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(invalid)?
        .to_owned();
    let password = data
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(invalid)?
        .to_owned();
    lease(
        template,
        Some(user),
        password,
        started + Duration::from_secs(ttl - 1),
    )
}
fn run(command: &mut Command, deadline: Instant) -> io::Result<Vec<u8>> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // Private, unlinked output file avoids pipe deadlock and never leaves a credential artifact.
    let path = std::env::temp_dir().join(format!(
        "pgproxy-credential-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(&path)
        .map_err(|_| io::Error::other("credential provider output unavailable"))?;
    // Unlink before launching: both descriptors retain the file but no path exposes secrets.
    std::fs::remove_file(&path)
        .map_err(|_| io::Error::other("credential provider output unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(output.try_clone()?)
        .spawn()
        .map_err(|_| io::Error::other("credential executable unavailable"))?;
    let mut result = loop {
        let output_len = match output.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => break Err(io::Error::other("credential output unavailable")),
        };
        if output_len > MAX_OUTPUT {
            break Err(io::Error::other("credential output limit exceeded"));
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(io::Error::other("credential provider failed")),
            Err(_) => break Err(io::Error::other("credential provider failed")),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            break Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        thread::sleep(Duration::from_millis(5));
    };
    // Descendants may keep writing the inherited descriptor even after the issuer
    // exits. Always terminate the private group, including on apparent success.
    #[cfg(unix)]
    {
        let group = nix::unistd::Pid::from_raw(child.id() as i32);
        // Use the OS signal API directly: minimal container images need not ship
        // /bin/kill, and silently ignoring executable failures leaves issuers alive.
        if let Err(error) = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL)
            && error != nix::errno::Errno::ESRCH
        {
            result = Err(io::Error::other("credential process cleanup failed"));
        }
    }
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result?;
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output.take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OUTPUT as usize {
        return Err(invalid());
    }
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn template() -> BackendCredentials {
        BackendCredentials {
            user: "app".into(),
            password: None,
            database: Some("app".into()),
            application_name: None,
        }
    }
    #[test]
    fn expires_and_redacts_invalid_credentials() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let bytes = serde_json::json!({"user":"dynamic","password":"secret","expires_at":now+30})
            .to_string();
        let grant = json_lease(bytes.as_bytes(), &template()).unwrap();
        assert_eq!(grant.credentials.user, "dynamic");
        assert!(grant.expires_at.unwrap() > Instant::now());
        assert!(!format!("{grant:?}").contains("secret"));
        assert!(json_lease(br#"{"password":"secret","expires_at":1}"#, &template()).is_err());
        assert!(
            json_lease(
                br#"{"password":"secret","expires_at":999999999999}"#,
                &template()
            )
            .is_err()
        );
    }
    #[test]
    fn command_timeout_output_and_failure_are_bounded_and_redacted() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let output = run(Command::new("/usr/bin/printf").arg("safe"), deadline).unwrap();
        assert_eq!(output, b"safe");
        assert!(
            run(
                Command::new("/usr/bin/head").args(["-c", "65537", "/dev/zero"]),
                deadline
            )
            .is_err()
        );
        let start = Instant::now();
        assert!(
            run(
                Command::new("/bin/sleep").arg("2"),
                start + Duration::from_millis(30)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        let error = run(&mut Command::new("/usr/bin/false"), deadline).unwrap_err();
        assert_eq!(error.to_string(), "credential provider failed");
    }
    #[test]
    fn aws_token_is_bound_to_candidate_endpoint_and_conservative_expiry() {
        let target = BackendTarget {
            host: "db.example".into(),
            port: 5432,
            database: None,
            user: None,
        };
        let started = Instant::now();
        let token = b"db.example:5432/?Action=connect&X-Amz-Signature=test\n".to_vec();
        let grant = aws_lease(token.clone(), &target, &template(), started).unwrap();
        assert_eq!(
            grant.expires_at.unwrap(),
            started + Duration::from_secs(840)
        );
        let alternate = BackendTarget {
            host: "other.example".into(),
            ..target
        };
        assert!(aws_lease(token, &alternate, &template(), started).is_err());
        assert!(
            aws_lease(
                b"issuer diagnostic instead of token".to_vec(),
                &alternate,
                &template(),
                started
            )
            .is_err()
        );
    }

    #[test]
    fn vault_dynamic_credentials_use_the_issuer_lease_and_reject_static_or_expired_data() {
        let started = Instant::now();
        let value =
            br#"{"lease_duration":10,"data":{"username":"leased-role","password":"private"}}"#;
        let grant = vault_lease(value, &template(), started).unwrap();
        assert_eq!(grant.credentials.user, "leased-role");
        assert_eq!(grant.expires_at.unwrap(), started + Duration::from_secs(9));
        assert!(
            vault_lease(
                br#"{"lease_duration":0,"data":{"username":"u","password":"p"}}"#,
                &template(),
                started
            )
            .is_err()
        );
        assert!(vault_lease(value, &template(), started - Duration::from_secs(20)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_credentials_are_rejected_without_waiting_for_a_writer() {
        let path = std::env::temp_dir().join(format!("pgproxy-fifo-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(
            Command::new("/usr/bin/mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let provider = CredentialConfig::File { path: path.clone() }
            .provider()
            .unwrap();
        let started = Instant::now();
        let result = provider.resolve(
            &BackendTarget {
                host: "localhost".into(),
                port: 5432,
                database: None,
                user: None,
            },
            &template(),
            started + Duration::from_millis(50),
        );
        std::fs::remove_file(path).unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[cfg(unix)]
    #[test]
    fn timed_out_command_cannot_leave_a_descendant_running() {
        let marker =
            std::env::temp_dir().join(format!("pgproxy-descendant-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        // Shell is used only as an adversarial test fixture; adapters launch
        // their operator-configured executable directly without a shell.
        let result = run(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("(sleep 0.15; printf leaked > \"$1\") & wait")
                .arg("fixture")
                .arg(&marker),
            Instant::now() + Duration::from_millis(30),
        );
        assert!(result.is_err());
        thread::sleep(Duration::from_millis(250));
        assert!(!marker.exists(), "timed-out issuer descendant survived");
    }

    #[test]
    fn unsafe_adapter_configuration_is_rejected() {
        assert!(
            CredentialConfig::Command {
                program: "relative".into(),
                args: vec![],
                timeout_secs: 5
            }
            .validate()
            .is_err()
        );
        assert!(
            CredentialConfig::Vault {
                role_path: "--bad".into(),
                program: "vault".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            CredentialConfig::Environment {
                password_variable: "SECRET=value".into(),
                user_variable: None,
                ttl_secs: 1
            }
            .validate()
            .is_err()
        );
    }
}
