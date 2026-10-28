//! A bounded pre-registered public-client OAuth profile for the Waypost MCP resource.
use super::*;
use serde::Deserialize;
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClient {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    pub clients: Vec<OAuthClient>,
}

pub(super) fn oauth_error(code: &'static str) -> Error {
    Error::new(code, "OAuth request could not be completed.")
}
/// Edge throttling happens before App dispatch, but OAuth clients still need the
/// protocol error shape and an explicit retry delay (never the API envelope).
#[cfg(any(test, all(feature = "cloudflare", target_arch = "wasm32")))]
pub(crate) fn rate_limited_response() -> Response {
    let mut response = Response::json(429, json!({"error":"temporarily_unavailable"}));
    response
        .headers
        .insert("cache-control".into(), "no-store".into());
    response.headers.insert("pragma".into(), "no-cache".into());
    response.headers.insert("retry-after".into(), "60".into());
    response
}

pub(super) fn parse_params(raw: &str) -> Result<BTreeMap<String, String>> {
    if raw.len() > 16384 {
        return Err(oauth_error("invalid_request"));
    }
    // Reject malformed percent encoding rather than normalizing ambiguous parameters.
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return Err(oauth_error("invalid_request"));
            }
            i += 2;
        }
        i += 1;
    }
    let mut out = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if k.contains('\u{fffd}')
            || v.contains('\u{fffd}')
            || out.insert(k.into_owned(), v.into_owned()).is_some()
        {
            return Err(oauth_error("invalid_request"));
        }
    }
    Ok(out)
}
impl<D: Database, O: ObjectStore> App<D, O> {
    pub fn with_oauth(mut self, config: OAuthConfig) -> Result<Self> {
        if self.oidc.is_none() || config.clients.is_empty() || config.clients.len() > 32 {
            return Err(Error::invalid(
                "OAuth requires accounts and 1–32 pre-registered clients.",
            ));
        }
        let origin = Url::parse(&self.config.public_origin)
            .map_err(|_| Error::invalid("Invalid OAuth issuer."))?;
        if origin.origin().ascii_serialization() != self.config.public_origin
            || (origin.scheme() != "https"
                && !(origin.scheme() == "http" && origin.host_str() == Some("127.0.0.1")))
        {
            return Err(Error::invalid(
                "OAuth requires HTTPS or literal loopback development origin.",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for c in &config.clients {
            if c.client_id.is_empty()
                || c.client_id.len() > 200
                || c.client_id.chars().any(char::is_control)
                || !ids.insert(c.client_id.clone())
                || c.name.is_empty()
                || c.name.len() > 200
                || c.name.chars().any(char::is_control)
                || c.redirect_uris.len() > 8
            {
                return Err(Error::invalid("Invalid OAuth client configuration."));
            }
            for r in &c.redirect_uris {
                let u = Url::parse(r).map_err(|_| Error::invalid("Invalid OAuth redirect."))?;
                if u.fragment().is_some()
                    || u.query().is_some()
                    || !u.username().is_empty()
                    || u.password().is_some()
                    || u.host_str().is_none()
                    || u.as_str() != r
                    || r.len() > 2048
                    || !(u.scheme() == "https"
                        || (u.scheme() == "http"
                            && matches!(u.host_str(), Some("127.0.0.1" | "[::1]"))))
                {
                    return Err(Error::invalid(
                        "Redirect must be an exact HTTPS or literal loopback URL without query/fragment.",
                    ));
                }
            }
        }
        self.oauth = Some(config);
        Ok(self)
    }
    pub(super) fn oauth_client(&self, id: &str) -> Result<&OAuthClient> {
        self.oauth
            .as_ref()
            .and_then(|c| c.clients.iter().find(|c| c.client_id == id))
            .ok_or_else(|| oauth_error("invalid_client"))
    }
    pub(super) fn oauth_resource(&self) -> String {
        format!("{}/mcp", self.config.public_origin)
    }
    pub(super) fn oauth_challenge(&self, response: &mut Response) {
        if self.oauth.is_some() && response.status == 401 {
            response.headers.insert("www-authenticate".into(),format!("Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"waypost\"",self.config.public_origin));
        }
    }
    pub(super) async fn oauth_handle(&self, r: &Request) -> Response {
        let result = self.oauth_action(r).await;
        let mut response = match result {
            Ok(r) => r,
            Err(e) => {
                let (code, status) = match e.code {
                    "invalid_request"
                    | "invalid_grant"
                    | "invalid_scope"
                    | "invalid_target"
                    | "unsupported_grant_type"
                    | "unsupported_response_type"
                    | "authorization_pending"
                    | "slow_down"
                    | "expired_token"
                    | "access_denied" => (e.code, 400),
                    "invalid_client" => ("invalid_client", 400),
                    "UNAUTHENTICATED" => ("access_denied", 401),
                    "FORBIDDEN" => ("access_denied", 403),
                    "NOT_FOUND" => ("invalid_request", 404),
                    "RATE_LIMITED" => ("temporarily_unavailable", 429),
                    "temporarily_unavailable" => ("temporarily_unavailable", 503),
                    "INTERNAL_ERROR" | "STORAGE_UNAVAILABLE" => ("server_error", 503),
                    _ => ("invalid_request", 400),
                };
                Response::json(status, json!({"error":code}))
            }
        };
        response
            .headers
            .insert("cache-control".into(), "no-store".into());
        response.headers.insert("pragma".into(), "no-cache".into());
        response
            .headers
            .insert("referrer-policy".into(), "no-referrer".into());
        response
    }
    async fn oauth_action(&self, r: &Request) -> Result<Response> {
        self.oauth.as_ref().ok_or_else(Error::not_found)?;
        if r.headers
            .get("origin")
            .is_some_and(|o| o != &self.config.public_origin)
        {
            return Err(Error::forbidden());
        }
        if r.method == "GET"
            && matches!(
                r.path.as_str(),
                "/.well-known/oauth-protected-resource/mcp"
                    | "/.well-known/oauth-protected-resource"
            )
        {
            return Ok(Response::json(
                200,
                json!({"resource":self.oauth_resource(),"authorization_servers":[self.config.public_origin],"scopes_supported":["waypost"],"bearer_methods_supported":["header"],"resource_name":"Waypost Space"}),
            ));
        }
        if r.method == "GET" && r.path == "/.well-known/oauth-authorization-server" {
            let origin = &self.config.public_origin;
            return Ok(Response::json(
                200,
                json!({"issuer":origin,"authorization_endpoint":format!("{origin}/oauth/authorize"),"token_endpoint":format!("{origin}/oauth/token"),"revocation_endpoint":format!("{origin}/oauth/revoke"),"device_authorization_endpoint":format!("{origin}/oauth/device_authorization"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"],"token_endpoint_auth_methods_supported":["none"],"revocation_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["waypost"],"authorization_response_iss_parameter_supported":true,"client_id_metadata_document_supported":false}),
            ));
        }
        if r.path == "/oauth/authorize" && r.method == "GET" {
            return self.oauth_authorize(r, parse_params(&r.query)?).await;
        }
        if r.path == "/oauth/consent" {
            let body = if r.method == "GET" {
                serde_json::to_value(parse_params(&r.query)?)
                    .map_err(|_| oauth_error("invalid_request"))?
            } else {
                crate::json::parse(&r.body, self.limits.max_json_bytes)?
            };
            return self.oauth_consent(r, body).await;
        }
        if r.path == "/oauth/device_consent" && r.method == "POST" {
            return self
                .oauth_device_consent(r, crate::json::parse(&r.body, self.limits.max_json_bytes)?)
                .await;
        }
        if r.method != "POST" {
            return Err(Error::not_found());
        }
        // Only public preregistered clients. Reject Basic/other authorization instead
        // of silently treating failed client authentication as anonymous.
        if r.headers.contains_key("authorization") {
            return Err(oauth_error("invalid_client"));
        }
        if r.headers
            .get("content-type")
            .and_then(|s| s.split(';').next())
            != Some("application/x-www-form-urlencoded")
        {
            return Err(oauth_error("invalid_request"));
        }
        let raw = std::str::from_utf8(&r.body).map_err(|_| oauth_error("invalid_request"))?;
        let params = parse_params(raw)?;
        let result = match r.path.as_str() {
            "/oauth/token" => self.oauth_token(params).await?,
            "/oauth/revoke" => self.oauth_revoke(params).await?,
            "/oauth/device_authorization" => self.oauth_device_authorization(params).await?,
            _ => return Err(Error::not_found()),
        };
        Ok(Response::json(200, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn edge_throttle_preserves_oauth_error_contract() {
        let response = rate_limited_response();
        assert_eq!(response.status, 429);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body, json!({"error":"temporarily_unavailable"}));
        assert_eq!(response.headers["retry-after"], "60");
        assert_eq!(response.headers["cache-control"], "no-store");
    }
    #[test]
    fn form_parameters_reject_ambiguity() {
        for raw in [
            "client_id=a&client_id=b",
            "x=%",
            "x=%ff",
            "x=%GG",
            "a=1&%61=2",
        ] {
            assert!(parse_params(raw).is_err(), "{raw}");
        }
        let parsed =
            parse_params("resource=https%3A%2F%2Fexample.test%2Fmcp&scope=waypost").unwrap();
        assert_eq!(parsed["resource"], "https://example.test/mcp");
        assert!(parse_params(&"a".repeat(16385)).is_err());
    }
}
