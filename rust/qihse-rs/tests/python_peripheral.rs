#![cfg(feature = "python-port")]
use qihse_rs::python_port::{browser, HardwareProfiler, UwpCodec};
use qihse_rs::python_peripheral::{parse_ipmi, parse_uwp_response, UwpError, UWP_HEADER_SIZE};

#[test]
fn native_hardware_profile_is_native_and_has_expected_units() {
    let profile = HardwareProfiler::get_profile().unwrap();
    assert!(!profile.preferred_backend.is_empty());
    assert!(profile.cache_line_bytes > 0);
    assert!(profile.l3_mb >= 0.0);
}

#[test]
fn thermal_sensor_parsing_and_clamped_headroom() {
    let sensors = "CPU Temp | a | b | c | 75.0 degrees C\nInlet Temp | a | b | c | 25 degrees C\nFan1 RPM | a | b | c | 900 RPM\nFan2 RPM | a | b | c | 1100 RPM";
    let telemetry = parse_ipmi("test", sensors, 85.0);
    assert_eq!(telemetry.cpu_max, Some(75.0));
    assert_eq!(telemetry.fan_avg, 1000);
    assert_eq!(telemetry.thermal_headroom_milli, 166);
    assert_eq!(parse_ipmi("test", "", 85.0).thermal_headroom_milli, 1000);
    assert_eq!(parse_ipmi("test", "CPU Temp | a | b | c | NaN degrees C", 85.0).cpu_max, None);
}

#[test]
fn uwp_frame_is_little_endian_and_rejects_unauthenticated_commands() {
    let mut codec = UwpCodec::new();
    assert_eq!(codec.command_frame(1, 2, b"protected"), Err(UwpError::Authentication));
    assert_eq!(codec.auth_frame("", "pw"), Err(UwpError::Authentication));
    let frame = codec.auth_frame("user", "pw").unwrap();
    assert_eq!(&frame[..4], b"QIHS");
    assert_eq!(&frame[4..7], &[1, 0, 1]);
    assert_eq!(u64::from_le_bytes(frame[7..UWP_HEADER_SIZE].try_into().unwrap()), 8);
    assert_eq!(&frame[UWP_HEADER_SIZE..], b"user\0pw\0");
    codec.accept_auth_reply("OK\r\n").unwrap();
    let command = codec.command_frame(1, 2, b"x").unwrap();
    assert_eq!(&command[..7], b"QIHS\x01\x01\x02");
    assert_eq!(&command[UWP_HEADER_SIZE..], b"x");
    assert_eq!(codec.accept_reply("ERR_PERM\r\n"), Err(UwpError::Permission));
    assert_eq!(codec.accept_reply("ERR_AUTH\r\n"), Err(UwpError::Authentication));
    assert!(!codec.is_authenticated());
    assert_eq!(parse_uwp_response("ERR_TOO_LARGE"), Err(UwpError::Protocol));
    assert_eq!(browser::SLOT_COUNT, 16_384);
    assert_eq!(browser::keyslot(b"{key}"), browser::keyslot(b"key"));
}
