//! Opt-in peripheral slice of the Python SDK. Hardware profiling calls the
//! native dispatcher; thermal decoding and UWP framing are pure Rust. This is
//! not a replacement for the Python thermal daemon or TLS UWP client/server.
use crate::ffi;
use std::ffi::CStr;

#[derive(Debug, Clone, PartialEq)]
pub struct HardwareProfile {
    pub preferred_backend: String,
    pub avx: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub sse42: bool,
    pub blas: bool,
    pub l1_kb: usize,
    pub l2_kb: usize,
    pub l3_mb: f64,
    pub cache_line_bytes: u32,
    pub numa_nodes: u32,
}

pub struct HardwareProfiler;
impl HardwareProfiler {
    pub fn get_profile() -> Result<HardwareProfile, &'static str> {
        let ptr = unsafe { ffi::qihse_hw_profile_create() };
        if ptr.is_null() { return Err("native hardware profile creation failed"); }
        let result = unsafe {
            let hw = &*ptr;
            let name = ffi::qihse_hw_backend_name(hw.preferred);
            if name.is_null() { Err("unknown native hardware backend") } else {
                Ok(HardwareProfile {
                    preferred_backend: CStr::from_ptr(name).to_string_lossy().into_owned(),
                    avx: hw.avx_available, avx2: hw.avx2_available,
                    avx512: hw.avx512_available, sse42: hw.sse42_available,
                    blas: hw.blas_available,
                    l1_kb: hw.cache.l1_data_size / 1024,
                    l2_kb: hw.cache.l2_size / 1024,
                    l3_mb: hw.cache.l3_size as f64 / (1024 * 1024) as f64,
                    cache_line_bytes: hw.cache.cache_line_size,
                    numa_nodes: hw.cache.numa_nodes,
                })
            }
        };
        unsafe { ffi::qihse_hw_profile_destroy(ptr) };
        result
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThermalTelemetry {
    pub node: String,
    pub cpu_temps: Vec<f64>,
    pub cpu_max: Option<f64>,
    pub cpu_avg: Option<f64>,
    pub inlet_temp: Option<f64>,
    pub exhaust_temp: Option<f64>,
    pub fan_rpms: Vec<(String, u32)>,
    pub fan_avg: u32,
    pub thermal_headroom_milli: u16,
}

/// Decode already-collected `ipmitool sdr type temperature/fan` output. This
/// does not execute commands or read a host-specific telemetry file.
pub fn parse_ipmi(node: &str, output: &str, tjmax: f64) -> ThermalTelemetry {
    let mut result = ThermalTelemetry {
        node: node.to_owned(), cpu_temps: Vec::new(), cpu_max: None,
        cpu_avg: None, inlet_temp: None, exhaust_temp: None,
        fan_rpms: Vec::new(), fan_avg: 0, thermal_headroom_milli: 1000,
    };
    for line in output.lines() {
        let fields: Vec<_> = line.split('|').map(str::trim).collect();
        if fields.len() < 5 { continue; }
        let name = fields[0];
        let value = fields[4].to_ascii_lowercase();
        if let Some((number, _)) = value.split_once("degrees c") {
            if let Some(temp) = number.split_whitespace().last().and_then(|n| n.parse::<f64>().ok()) {
                if temp.is_finite() {
                    let lower = name.to_ascii_lowercase();
                    if lower.contains("inlet") { result.inlet_temp = Some(temp); }
                    else if lower.contains("exhaust") { result.exhaust_temp = Some(temp); }
                    else if lower.contains("temp") { result.cpu_temps.push(temp); }
                }
            }
        }
        if let Some((number, _)) = value.split_once("rpm") {
            if let Some(rpm) = number.split_whitespace().last().and_then(|n| n.parse::<u32>().ok()) {
                if rpm > 0 { result.fan_rpms.push((name.to_owned(), rpm)); }
            }
        }
    }
    if !result.cpu_temps.is_empty() {
        result.cpu_max = result.cpu_temps.iter().copied().reduce(f64::max);
        result.cpu_avg = Some((result.cpu_temps.iter().sum::<f64>() / result.cpu_temps.len() as f64 * 10.0).round() / 10.0);
    }
    if !result.fan_rpms.is_empty() {
        result.fan_avg = (result.fan_rpms.iter().map(|(_, rpm)| u64::from(*rpm)).sum::<u64>() / result.fan_rpms.len() as u64) as u32;
    }
    let ambient = result.inlet_temp.unwrap_or(25.0);
    if let Some(cpu_max) = result.cpu_max {
        if tjmax.is_finite() && tjmax > ambient {
            result.thermal_headroom_milli = ((1.0 - (cpu_max - ambient) / (tjmax - ambient))
                .clamp(0.0, 1.0) * 1000.0) as u16;
        }
    }
    result
}

pub const UWP_MAGIC: [u8; 4] = *b"QIHS";
pub const UWP_VERSION: u8 = 1;
pub const UWP_HEADER_SIZE: usize = 15;
pub const UWP_MAX_PAYLOAD: usize = 16 * 1024 * 1024;
pub const UWP_TARGET_AUTH: u8 = 0;
pub const UWP_TARGET_KV: u8 = 1;
pub const UWP_TARGET_VECTOR: u8 = 2;
pub const UWP_TARGET_DOC: u8 = 3;
pub const UWP_TARGET_TSDB: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UwpError { Authentication, Permission, RateLimited, Protocol, PayloadTooLarge }

/// A transport-independent UWP codec: the caller must supply a verified TLS
/// channel. No cleartext socket, credential persistence or retry is provided.
pub struct UwpCodec { authenticated: bool }
impl UwpCodec {
    pub fn new() -> Self { Self { authenticated: false } }
    pub fn is_authenticated(&self) -> bool { self.authenticated }
    pub fn auth_frame(&self, username: &str, password: &str) -> Result<Vec<u8>, UwpError> {
        if username.is_empty() || password.is_empty() || username.contains('\0') || password.contains('\0') {
            return Err(UwpError::Authentication);
        }
        let mut data = Vec::with_capacity(username.len() + password.len() + 2);
        data.extend_from_slice(username.as_bytes()); data.push(0);
        data.extend_from_slice(password.as_bytes()); data.push(0);
        encode_frame(UWP_TARGET_AUTH, 1, &data)
    }
    pub fn accept_auth_reply(&mut self, response: &str) -> Result<(), UwpError> {
        self.authenticated = false;
        parse_uwp_response(response)?;
        if response.trim() != "OK" { return Err(UwpError::Authentication); }
        self.authenticated = true;
        Ok(())
    }
    pub fn command_frame(&self, target: u8, command: u8, payload: &[u8]) -> Result<Vec<u8>, UwpError> {
        if !self.authenticated || target == UWP_TARGET_AUTH { return Err(UwpError::Authentication); }
        encode_frame(target, command, payload)
    }
    pub fn accept_reply(&mut self, response: &str) -> Result<String, UwpError> {
        let result = parse_uwp_response(response);
        if matches!(result, Err(UwpError::Authentication)) { self.authenticated = false; }
        result
    }
}
impl Default for UwpCodec { fn default() -> Self { Self::new() } }

fn encode_frame(target: u8, command: u8, payload: &[u8]) -> Result<Vec<u8>, UwpError> {
    if payload.len() > UWP_MAX_PAYLOAD { return Err(UwpError::PayloadTooLarge); }
    let mut frame = Vec::with_capacity(UWP_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&UWP_MAGIC);
    frame.extend_from_slice(&[UWP_VERSION, target, command]);
    frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn parse_uwp_response(line: &str) -> Result<String, UwpError> {
    let line = line.trim();
    match line {
        "ERR_AUTH" => Err(UwpError::Authentication),
        "ERR_PERM" => Err(UwpError::Permission),
        "ERR_RATE_LIMITED" => Err(UwpError::RateLimited),
        "ERR_MAGIC" | "ERR_VERSION" | "ERR_LEN" | "ERR_TOO_LARGE" | "ERR_DISPATCH" => Err(UwpError::Protocol),
        _ if line.starts_with("ERR") => Err(UwpError::Protocol),
        _ => Ok(line.to_owned()),
    }
}
