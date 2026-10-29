pub mod domain;
pub mod error;
pub mod http;
mod json;
#[cfg(feature = "native")]
pub mod native;
mod service;
pub mod storage;
pub use http::{Request, Response};
pub use service::{App, Clock, Config, Limits, SystemClock};

#[cfg(all(feature = "cloudflare", target_arch = "wasm32"))]
mod cloudflare;

pub use service::accounts_oidc;

pub use service::oauth::{OAuthClient, OAuthConfig};

pub use service::oauth_client_registry;
pub use service::oauth_client_registry::{
    OAuthClientDiscoveryConfig, OAuthClientMetadataDocument, OAuthClientMetadataFetcher,
};
