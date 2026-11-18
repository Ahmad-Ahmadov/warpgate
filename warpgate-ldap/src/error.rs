use thiserror::Error;
use warpgate_tls::RustlsSetupError;

pub type Result<T> = std::result::Result<T, LdapError>;

#[derive(Error, Debug)]
pub enum LdapError {
    #[error("LDAP connection failed: {0}")]
    ConnectionFailed(String),

    #[error("LDAP authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("LDAP query failed: {0}")]
    QueryFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("LDAP error: {0}")]
    LdapClientError(#[from] Box<ldap3::LdapError>),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("rustls setup: {0}")]
    RustlSetup(#[from] RustlsSetupError),

    #[error("cannot determine username for user DN: {0}")]
    NoUsername(String),

    #[error("cannot determine UUID for user DN: {0}")]
    NoUUID(String),

    #[error("LDAP lookup matched {count} entries, expected at most one: {filter}")]
    AmbiguousMatch { filter: String, count: usize },

    /// A user's password is only ever sent over LDAPS or StartTLS.
    #[error(
        "refusing to send a user's password over an unencrypted LDAP connection; set the server's TLS mode to Preferred or Required"
    )]
    InsecureTransport,

    /// The directory could not answer a user's bind — a server-side or
    /// configuration problem rather than a verdict on the password.
    #[error("LDAP bind failed with result code {result_code}: {text}")]
    BindFailed { result_code: u32, text: String },
}
