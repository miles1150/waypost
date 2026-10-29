//! Cloudflare Workers adapter shared by every product: D1 statements, request
//! body limits, response conversion and the redacted structured error log.
use crate::{
    error::{Error, Result},
    http::Response,
    storage::driver::{Database, Row, Statement, Value as Sql},
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wasm_bindgen::JsValue;
use worker::{D1DatabaseSession, D1PreparedStatement, D1Result};

pub(crate) struct D1Store {
    pub(crate) session: D1DatabaseSession,
}
impl D1Store {
    pub(crate) fn new(session: D1DatabaseSession) -> Self {
        Self { session }
    }
    fn prepare(&self, statement: Statement) -> Result<D1PreparedStatement> {
        if statement.parameters.len() > 100 || statement.sql.len() > 100_000 {
            return Err(Error::new(
                "RESOURCE_LIMIT",
                "Statement exceeds the D1 deployment limit.",
            ));
        }
        let parameters = statement
            .parameters
            .into_iter()
            .map(|v| match v {
                Sql::Null => JsValue::NULL,
                Sql::Text(s) => JsValue::from_str(&s),
                Sql::Integer(n) => {
                    if n.unsigned_abs() <= 9_007_199_254_740_991 {
                        JsValue::from_f64(n as f64)
                    } else {
                        JsValue::from_str(&n.to_string())
                    }
                }
                Sql::Blob(bytes) => js_sys::Uint8Array::from(bytes.as_slice()).into(),
            })
            .collect::<Vec<_>>();
        self.session
            .prepare(statement.sql)
            .bind(&parameters)
            .map_err(|_| Error::internal("D1 statement bindings"))
    }
}
fn d1_error(error: worker::Error) -> Error {
    let message = error.to_string().to_ascii_lowercase();
    if [
        "constraint",
        "syntax error",
        "no such table",
        "no such column",
        "datatype mismatch",
        "bind",
    ]
    .iter()
    .any(|label| message.contains(label))
    {
        Error::internal("D1 statement or schema")
    } else {
        Error::storage()
    }
}
fn result_rows(result: D1Result) -> Result<Vec<Row>> {
    if !result.success() {
        return Err(Error::storage());
    }
    let rows = result
        .results::<BTreeMap<String, Value>>()
        .map_err(|_| Error::internal("D1 row decoding"))?;
    rows.into_iter()
        .map(|r| {
            r.into_iter()
                .map(|(name, value)| {
                    let value = match value {
                        Value::Null => Sql::Null,
                        Value::String(s) => Sql::Text(s),
                        Value::Number(n) => Sql::Integer(n.as_i64().ok_or_else(Error::storage)?),
                        Value::Array(a) => Sql::Blob(
                            a.into_iter()
                                .map(|v| {
                                    v.as_u64()
                                        .filter(|v| *v <= 255)
                                        .map(|v| v as u8)
                                        .ok_or_else(Error::storage)
                                })
                                .collect::<Result<Vec<_>>>()?,
                        ),
                        _ => return Err(Error::storage()),
                    };
                    Ok((name, value))
                })
                .collect()
        })
        .collect()
}
impl Database for D1Store {
    async fn query(&self, statement: Statement) -> Result<Vec<Row>> {
        result_rows(self.prepare(statement)?.all().await.map_err(d1_error)?)
    }
    async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<Vec<Row>>> {
        let statements = statements
            .into_iter()
            .map(|s| self.prepare(s))
            .collect::<Result<Vec<_>>>()?;
        self.session
            .batch(statements)
            .await
            .map_err(d1_error)?
            .into_iter()
            .map(result_rows)
            .collect()
    }
}

pub(crate) fn error_response(error: Error) -> worker::Result<worker::Response> {
    worker::Response::from_json(&json!({"ok":false,"error":error.value()}))
        .map(|r| r.with_status(error.status()))
}

/// Error log line: error code, route, and request id. Nothing else.
pub(crate) fn log_structured(route: &str, code: &str, request_id: Option<&str>) {
    let error_code = if code.len() <= 64
        && code
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
    {
        code
    } else {
        "INTERNAL_ERROR"
    };
    let route = if route.len() <= 160
        && route.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b' ' | b'/' | b':' | b'_' | b'-' | b'.')
        }) {
        route
    } else {
        "UNKNOWN /unknown"
    };
    let request_id = request_id.filter(|id| crate::domain::check_request_id(id).is_ok());
    let line = serde_json::to_string(&json!({
        "error_code": error_code,
        "route": route,
        "request_id": request_id,
    }))
    .unwrap_or_else(|_| {
        r#"{"error_code":"INTERNAL_ERROR","route":"UNKNOWN /unknown","request_id":null}"#.into()
    });
    worker::console_error!("{}", line);
}

pub(crate) fn log_and_error(route: &str, error: Error) -> worker::Result<worker::Response> {
    log_structured(route, error.code, None);
    error_response(error)
}

pub(crate) fn log_json_error(route: &str, body: &[u8]) {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("INTERNAL_ERROR");
    let request_id = parsed
        .as_ref()
        .and_then(|value| value.get("request_id"))
        .and_then(Value::as_str);
    log_structured(route, code, request_id);
}
pub(crate) fn convert(response: Response) -> worker::Result<worker::Response> {
    let mut r = worker::Response::from_bytes(response.body)?.with_status(response.status);
    for (k, v) in response.headers {
        r.headers_mut().set(&k, &v)?;
    }
    Ok(r)
}

/// Read a request body, refusing anything over `max` bytes.
pub(crate) async fn read_body(raw: &mut worker::Request, max: usize) -> Result<Vec<u8>> {
    let mut body = vec![];
    if raw.inner().body().is_some() {
        let mut stream = raw
            .stream()
            .map_err(|_| Error::new("INVALID_ARGUMENT", "Unreadable request body."))?;
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|_| Error::new("INVALID_ARGUMENT", "Unreadable request body."))?;
            if body.len() + chunk.len() > max {
                return Err(Error::new(
                    "RESOURCE_LIMIT",
                    "Request exceeds Worker deployment limit.",
                ));
            }
            body.extend(chunk);
        }
    }
    Ok(body)
}

/// Headers every product response carries.
pub(crate) fn harden(response: &mut worker::Response, https: bool) -> worker::Result<()> {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
    ] {
        response.headers_mut().set(name, value)?;
    }
    if https {
        response
            .headers_mut()
            .set("strict-transport-security", "max-age=31536000")?;
    }
    Ok(())
}
