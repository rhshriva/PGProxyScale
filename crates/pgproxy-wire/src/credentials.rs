//! Late-bound backend credentials. Providers must never include secrets in errors or Debug.
use crate::{BackendCredentials, BackendTarget};
use std::{fmt::Debug, io, time::Instant};

pub struct CredentialLease {
    pub credentials: BackendCredentials,
    /// Physical connections may not be handed out after this deadline.
    pub expires_at: Option<Instant>,
}
impl Debug for CredentialLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialLease")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
pub trait CredentialProvider: Debug + Send + Sync {
    fn resolve(
        &self,
        target: &BackendTarget,
        template: &BackendCredentials,
        deadline: Instant,
    ) -> io::Result<CredentialLease>;
    /// Stable configuration identity; never a credential/token.
    fn pool_identity(&self) -> String;
}
