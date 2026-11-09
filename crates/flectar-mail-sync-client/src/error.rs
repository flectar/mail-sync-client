use flectar_mail_sync_proto::ErrorCode;
use std::time::Duration;

/// An error a [`crate::Store`] reports.
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not reach the sync server: {0}")]
    Network(#[source] reqwest::Error),
    #[error("the sync server answered {status}: {message}")]
    Server {
        status: u16,
        code: ErrorCode,
        message: String,
        /// From `Retry-After`, when the server sent one.
        retry_after: Option<Duration>,
    },
    #[error("the sync server sent something malformed: {0}")]
    Malformed(String),
    /// The server contradicted what this device verified before: a forked
    /// or rolled-back chain, or a key that does not match its commitment.
    #[error("the sync server cannot be trusted: {0}")]
    Untrusted(&'static str),
    /// The server didn't accept this device's login, and didn't say it was
    /// removed. It may not know the device, having lost the operation that
    /// added it to a restore from backup, which another device appends
    /// again; or the signature didn't check, as when the server's address
    /// is not the one the device signs for. Not proof of removal: keep the
    /// device's state and try again later. [`Error::Removed`] and
    /// [`Error::GroupDeleted`] are the final answers.
    #[error("the sync server did not accept this device's login")]
    LoginRefused,
    #[error("this device was removed from the sync group")]
    Removed,
    #[error("the sync group was deleted")]
    GroupDeleted,
    /// The group's free trial or paid period ended on a server that
    /// charges. Uploads wait for a payment; downloads go on.
    #[error("the sync subscription has ended")]
    PaymentRequired,
    /// A checkout was refused: the group already has a subscription, which
    /// may still be waiting for its first payment. Open the page that
    /// manages it, [`crate::SyncClient::manage_billing`], instead.
    #[error("the sync group already has a subscription")]
    AlreadySubscribed,
    #[error("no sync group on this server uses that recovery code")]
    UnknownRecoveryCode,
    /// No such code: it was mistyped, never made, or this server doesn't
    /// take codes.
    #[error("that code doesn't exist")]
    CodeUnknown,
    #[error("that code was already used")]
    CodeUsed,
    #[error("that code has expired")]
    CodeExpired,
    #[error("the other device declined")]
    Declined,
    #[error("the pairing expired")]
    PairingExpired,
    #[error("this is not a Flectar Mail Sync pairing code")]
    NotAPairingCode,
    #[error(transparent)]
    Crypto(#[from] flectar_mail_sync_crypto::Error),
    #[error("could not store sync state: {0}")]
    Store(#[source] StoreError),
}

impl Error {
    /// The server's error code, when the server answered with one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Server { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub(crate) fn status(&self) -> Option<u16> {
        match self {
            Self::Server { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether trying again later may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network(_) | Self::LoginRefused => true,
            // A full chain stays full.
            Self::Server {
                code: ErrorCode::ChainFull,
                ..
            } => false,
            // The server kept losing login challenges, as while it restarts.
            Self::Server {
                code: ErrorCode::ChallengeExpired,
                ..
            } => true,
            Self::Server { status, .. } => matches!(*status, 408 | 429) || *status >= 500,
            _ => false,
        }
    }
}

impl From<reqwest::Error> for Error {
    /// Without the request's address, which errors carry into logs and
    /// messages: a file's upload or download address works for anyone who
    /// has it until it expires.
    fn from(error: reqwest::Error) -> Self {
        let error = error.without_url();
        if error.is_decode() {
            Self::Malformed(error.to_string())
        } else {
            Self::Network(error)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, code: ErrorCode) -> Error {
        Error::Server {
            status,
            code,
            message: String::new(),
            retry_after: None,
        }
    }

    #[tokio::test]
    async fn network_errors_keep_the_address_out() {
        // As the app does, which brings its own TLS provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let unreachable = "http://127.0.0.1:9/files/1?X-Amz-Signature=0123abcd";
        let error: Error = reqwest::Client::new()
            .get(unreachable)
            .send()
            .await
            .unwrap_err()
            .into();
        assert!(matches!(error, Error::Network(_)), "{error:?}");
        assert!(!format!("{error} {error:?}").contains("X-Amz-Signature"));
    }

    #[test]
    fn only_what_may_pass_later_is_worth_retrying() {
        assert!(!answer(507, ErrorCode::ChainFull).is_transient());
        assert!(answer(503, ErrorCode::Unknown).is_transient());
        assert!(answer(429, ErrorCode::RateLimited).is_transient());
        assert!(answer(408, ErrorCode::RequestTimeout).is_transient());
        assert!(answer(408, ErrorCode::Unknown).is_transient());
        assert!(!answer(409, ErrorCode::Conflict).is_transient());
        assert!(Error::LoginRefused.is_transient());
        assert!(answer(401, ErrorCode::ChallengeExpired).is_transient());
        assert!(!Error::Removed.is_transient());
        assert!(!Error::GroupDeleted.is_transient());
    }
}
