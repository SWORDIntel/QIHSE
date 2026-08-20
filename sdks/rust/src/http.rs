//! HTTP/REST client for QIHSE HTTP API

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}: {}", self.status, self.message)
    }
}

impl std::error::Error for HttpError {}

/// HTTP response
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn ok(&self) -> bool {
        self.status < 400
    }

    pub fn raise_for_status(&self) -> Result<(), HttpError> {
        if self.status >= 400 {
            Err(HttpError { status: self.status, message: self.text() })
        } else {
            Ok(())
        }
    }
}

/// HTTP method
#[derive(Debug, Clone, Copy)]
pub enum Method {
    Get, Post, Put, Delete, Patch,
}

impl Method {
    fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET", Method::Post => "POST",
            Method::Put => "PUT", Method::Delete => "DELETE",
            Method::Patch => "PATCH",
        }
    }
}

/// HTTP client
pub struct HttpClient {
    host: String,
    port: u16,
    timeout: Duration,
}

impl HttpClient {
    pub fn new(host: &str, port: u16) -> Self {
        HttpClient { host: host.to_string(), port, timeout: Duration::from_secs(30) }
    }

    pub fn timeout(mut self, dur: Duration) -> Self {
        self.timeout = dur;
        self
    }

    pub fn request(&self, method: Method, path: &str, body: Option<&[u8]>) -> Result<Response, HttpError> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|_| HttpError { status: 0, message: "Invalid address".into() })?,
            self.timeout
        ).map_err(|e| HttpError { status: 0, message: e.to_string() })?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let body_len = body.map(|b| b.len()).unwrap_or(0);
        let req = format!(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            method.as_str(), path, self.host, self.port, body_len
        );
        stream.write_all(req.as_bytes()).map_err(|e| HttpError { status: 0, message: e.to_string() })?;
        if let Some(b) = body {
            stream.write_all(b).map_err(|e| HttpError { status: 0, message: e.to_string() })?;
        }

        let mut resp_buf = Vec::new();
        stream.read_to_end(&mut resp_buf).map_err(|e| HttpError { status: 0, message: e.to_string() })?;

        let header_end = resp_buf.windows(4).position(|w| w == b"\r\n\r\n")
            .ok_or(HttpError { status: 0, message: "Malformed response".into() })?;
        let header_str = String::from_utf8_lossy(&resp_buf[..header_end]);
        let body = resp_buf[header_end + 4..].to_vec();

        let mut lines = header_str.lines();
        let status_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(500);

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        Ok(Response { status, headers, body })
    }

    pub fn get(&self, path: &str) -> Result<Response, HttpError> {
        self.request(Method::Get, path, None)
    }

    pub fn post(&self, path: &str, body: &[u8]) -> Result<Response, HttpError> {
        self.request(Method::Post, path, Some(body))
    }

    pub fn put(&self, path: &str, body: &[u8]) -> Result<Response, HttpError> {
        self.request(Method::Put, path, Some(body))
    }

    pub fn delete(&self, path: &str) -> Result<Response, HttpError> {
        self.request(Method::Delete, path, None)
    }
}
