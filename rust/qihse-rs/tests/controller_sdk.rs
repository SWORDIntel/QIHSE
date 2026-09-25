//! Integration tests for the pure-std controller SDK (`qihse_rs::controller`).
//!
//! Every test drives the public client against an in-process mock controller:
//! a `std::net::TcpListener` bound to `127.0.0.1:0` (ephemeral port) that
//! records each RESP command it receives and replays scripted replies. No
//! external services, no absolute paths.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use qihse_rs::controller::{
    CasPrecondition, ControllerClient, ControllerConfig, ControllerError, Credentials, Reply,
};

// ============================================================================
// Mock controller
// ============================================================================

enum Step {
    /// Read one command (recording it), then send these bytes.
    Reply(Vec<u8>),
    /// Read one command (recording it), send these bytes, then close —
    /// simulates a peer dying mid-reply.
    Truncate(Vec<u8>),
    /// Never reply; block until the peer closes (drives client timeouts).
    Hold,
}

struct Mock {
    addr: SocketAddr,
    cmds: mpsc::Receiver<Vec<Vec<u8>>>,
    done: thread::JoinHandle<()>,
}

impl Mock {
    /// Commands recorded so far (each is the decoded argument list).
    fn recorded(&self) -> Vec<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        while let Ok(cmd) = self.cmds.try_recv() {
            out.push(cmd);
        }
        out
    }

    fn join(self) {
        self.done.join().expect("mock thread panicked");
    }
}

fn spawn_mock(steps: Vec<Step>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let done = thread::spawn(move || {
        let (mut sock, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(_) => return,
        };
        for step in &steps {
            match step {
                Step::Reply(bytes) | Step::Truncate(bytes) => {
                    let cmd = match read_command(&mut sock) {
                        Some(c) => c,
                        None => return,
                    };
                    let _ = tx.send(cmd);
                    if sock.write_all(bytes).is_err() {
                        return;
                    }
                    if matches!(step, Step::Truncate(_)) {
                        let _ = sock.shutdown(Shutdown::Both);
                        return;
                    }
                }
                Step::Hold => break,
            }
        }
        // Hold the connection (discarding bytes) until the peer goes away.
        let mut sink = [0u8; 1024];
        loop {
            match sock.read(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    Mock { addr, cmds: rx, done }
}

fn read_line_s(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).ok()?;
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Some(line);
        }
        line.push(byte[0]);
    }
}

/// Read exactly one complete RESP command (array of bulk strings).
fn read_command(stream: &mut TcpStream) -> Option<Vec<Vec<u8>>> {
    let header = read_line_s(stream)?;
    if *header.first()? != b'*' {
        return None;
    }
    let argc: usize = std::str::from_utf8(&header[1..]).ok()?.parse().ok()?;
    let mut out = Vec::with_capacity(argc);
    for _ in 0..argc {
        let item_header = read_line_s(stream)?;
        if *item_header.first()? != b'$' {
            return None;
        }
        let len: usize = std::str::from_utf8(&item_header[1..]).ok()?.parse().ok()?;
        let mut item = vec![0u8; len];
        stream.read_exact(&mut item).ok()?;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).ok()?;
        out.push(item);
    }
    Some(out)
}

// ============================================================================
// Helpers
// ============================================================================

fn config_for(addr: &SocketAddr, credentials: Credentials) -> ControllerConfig {
    let mut config = ControllerConfig::new(addr.ip().to_string(), addr.port(), credentials);
    config.timeout = Duration::from_millis(2000);
    config
}

const INT_ONE: &[u8] = b":1\r\n";
const OK: &[u8] = b"+OK\r\n";

// ============================================================================
// Connection + authentication model
// ============================================================================

#[test]
fn connect_authenticates_when_credentials_supplied() {
    let mock = spawn_mock(vec![
        Step::Reply(OK.to_vec()),
        Step::Reply(b"+PONG\r\n".to_vec()),
    ]);
    let creds = Credentials::Password {
        username: "controller".into(),
        password: "s3cret".into(),
    };
    let mut client = ControllerClient::connect(&config_for(&mock.addr, creds)).unwrap();
    assert!(client.is_connected());

    let reply = client.call(&[b"PING"]).unwrap();
    assert_eq!(reply, Reply::Simple("PONG".into()));

    let recorded = mock.recorded();
    assert_eq!(
        recorded[0],
        vec![b"AUTH".to_vec(), b"controller".to_vec(), b"s3cret".to_vec()]
    );
    assert_eq!(recorded[1], vec![b"PING".to_vec()]);
    drop(client);
    mock.join();
}

#[test]
fn connect_without_credentials_sends_no_ambient_auth() {
    let mock = spawn_mock(vec![Step::Reply(b"+PONG\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    client.call(&[b"PING"]).unwrap();

    // Exactly one command on the wire: no fabricated AUTH, ever.
    assert_eq!(mock.recorded(), vec![vec![b"PING".to_vec()]]);
    drop(client);
    mock.join();
}

#[test]
fn connect_refused_credentials_is_a_server_error() {
    let mock = spawn_mock(vec![Step::Reply(b"-ERR bad credentials\r\n".to_vec())]);
    let creds = Credentials::Password {
        username: "controller".into(),
        password: "wrong".into(),
    };
    match ControllerClient::connect(&config_for(&mock.addr, creds)) {
        Err(ControllerError::Server { class, message }) => {
            assert_eq!(class, "ERR");
            assert_eq!(message, "bad credentials");
        }
        other => panic!("expected Server error, got {other:?}"),
    }
    mock.join();
}

#[test]
fn connect_refused_is_a_transport_error() {
    // Reserve an ephemeral port, then free it so nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let err =
        ControllerClient::connect(&config_for(&addr, Credentials::Unauthenticated)).unwrap_err();
    assert!(matches!(err, ControllerError::Transport(_)), "got {err:?}");
}

#[test]
fn invalid_config_is_rejected_without_touching_the_network() {
    let mut config = ControllerConfig::new("127.0.0.1", 6380, Credentials::Unauthenticated);
    config.host = String::new();
    assert!(matches!(
        ControllerClient::connect(&config).unwrap_err(),
        ControllerError::InvalidConfig(_)
    ));
    let config = ControllerConfig::new("127.0.0.1", 0, Credentials::Unauthenticated);
    assert!(matches!(
        ControllerClient::connect(&config).unwrap_err(),
        ControllerError::InvalidConfig(_)
    ));
}

// ============================================================================
// Negative authorization (AGENTS.md invariant 3 for protocol adapters)
// ============================================================================

#[test]
fn low_clearance_denial_surfaces_no_payload() {
    // A low-clearance principal asks for a high object on the direct-ID path
    // and on the watch path. The controller denies both; the SDK must surface
    // the denial (class + message) with no object payload disclosure.
    let denial = b"-NOPERM clearance below object classification\r\n".to_vec();
    let mock = spawn_mock(vec![
        Step::Reply(OK.to_vec()), // AUTH accepted: the principal IS authenticated…
        Step::Reply(denial.clone()), // …and still denied the high object
        Step::Reply(denial.clone()),
    ]);
    let creds = Credentials::Password {
        username: "observer-low".into(),
        password: "pw".into(),
    };
    let mut client = ControllerClient::connect(&config_for(&mock.addr, creds)).unwrap();

    let err = client.object_get("ns-classified", "vm-secret").unwrap_err();
    match &err {
        ControllerError::Server { class, message } => {
            assert_eq!(class, "NOPERM");
            assert_eq!(message, "clearance below object classification");
        }
        other => panic!("expected Server denial, got {other:?}"),
    }
    // No payload disclosure: the error text carries only the server's denial.
    let text = err.to_string();
    assert!(!text.contains("vm-secret-payload"));
    assert!(!text.contains("SECRET"));

    let err = client.watch_next(1).unwrap_err();
    assert!(matches!(&err, ControllerError::Server { class, .. } if class == "NOPERM"));

    // A denial is a reply, not a transport failure: the connection survives.
    assert!(client.is_connected());
    drop(client);
    mock.join();
}

// ============================================================================
// Framing round-trips
// ============================================================================

#[test]
fn node_list_frame_is_exact_and_nested_reply_parses() {
    let reply = b"*2\r\n$6\r\nnode-1\r\n*2\r\n:7\r\n$8\r\nattested\r\n".to_vec();
    let mock = spawn_mock(vec![Step::Reply(reply)]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    let reply = client.node_list().unwrap();
    let items = reply.as_array().unwrap();
    assert_eq!(items[0].as_bytes(), Some(&b"node-1"[..]));
    let inner = items[1].as_array().unwrap();
    assert_eq!(inner[0].as_i64(), Some(7));
    assert_eq!(inner[1].as_str(), Some("attested"));

    assert_eq!(
        mock.recorded(),
        vec![vec![
            b"FEDERATION".to_vec(),
            b"NODE.LIST".to_vec()
        ]]
    );
    drop(client);
    mock.join();
}

#[test]
fn object_cas_carries_explicit_generation_preconditions() {
    let mock = spawn_mock(vec![Step::Reply(b":1\r\n".to_vec()), Step::Reply(b":0\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    // Binary value with embedded CRLF/NUL must arrive byte-exact.
    let value = b"{\"cpu\":4}\r\n\x00";
    assert!(client
        .object_cas("ns-1", "vm-1", value, CasPrecondition::CreateOnly)
        .unwrap());
    assert!(!client
        .object_cas("ns-1", "vm-1", value, CasPrecondition::IfGenerationIs(7))
        .unwrap());

    let recorded = mock.recorded();
    assert_eq!(recorded[0][4], value.to_vec());
    assert_eq!(recorded[0][5], b"0".to_vec()); // create-only
    assert_eq!(recorded[0][2], b"ns-1".to_vec());
    assert_eq!(recorded[0][3], b"vm-1".to_vec());
    assert_eq!(recorded[1][5], b"7".to_vec()); // explicit expected generation
    drop(client);
    mock.join();
}

#[test]
fn event_append_payload_is_byte_exact_and_returns_cursor() {
    let mock = spawn_mock(vec![Step::Reply(b":42\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    let payload = b"bin\x00\r\ndata";
    let offset = client.event_append("vm.created", "vm-1", Some(payload)).unwrap();
    assert_eq!(offset, 42);

    let recorded = mock.recorded();
    assert_eq!(recorded[0].len(), 5); // FEDERATION EVENT.APPEND type rid payload
    assert_eq!(recorded[0][4], payload.to_vec());
    drop(client);
    mock.join();
}

// ============================================================================
// Error mapping over the wire
// ============================================================================

#[test]
fn server_error_class_and_message_map_verbatim() {
    let mock = spawn_mock(vec![Step::Reply(b"-NOPERM caller lacks clearance\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    match client.node_get("node-1").unwrap_err() {
        ControllerError::Server { class, message } => {
            assert_eq!(class, "NOPERM");
            assert_eq!(message, "caller lacks clearance");
        }
        other => panic!("expected Server, got {other:?}"),
    }
    drop(client);
    mock.join();
}

#[test]
fn class_only_error_maps_with_empty_message() {
    let mock = spawn_mock(vec![Step::Reply(b"-BUSY\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    match client.epoch_next().unwrap_err() {
        ControllerError::Server { class, message } => {
            assert_eq!(class, "BUSY");
            assert_eq!(message, "");
        }
        other => panic!("expected Server, got {other:?}"),
    }
    drop(client);
    mock.join();
}

// ============================================================================
// Decoder bounds over a real socket
// ============================================================================

#[test]
fn oversized_bulk_reply_is_rejected_and_kills_connection() {
    let header = format!("${}\r\n", 16 * 1024 * 1024 + 1).into_bytes();
    let mock = spawn_mock(vec![Step::Reply(header)]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    match client.node_list().unwrap_err() {
        ControllerError::OversizedBulk { declared } => assert_eq!(declared, 16 * 1024 * 1024 + 1),
        other => panic!("expected OversizedBulk, got {other:?}"),
    }
    assert!(!client.is_connected());
    assert!(matches!(
        client.node_list().unwrap_err(),
        ControllerError::Closed
    ));
    drop(client);
    mock.join();
}

#[test]
fn too_many_items_reply_is_rejected() {
    let mock = spawn_mock(vec![Step::Reply(b"*1048577\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    match client.node_list().unwrap_err() {
        ControllerError::TooManyItems { declared } => assert_eq!(declared, 1_048_577),
        other => panic!("expected TooManyItems, got {other:?}"),
    }
    drop(client);
    mock.join();
}

#[test]
fn too_deep_reply_is_rejected() {
    let mut deep = Vec::new();
    for _ in 0..33 {
        deep.extend_from_slice(b"*1\r\n");
    }
    let mock = spawn_mock(vec![Step::Reply(deep)]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    match client.node_list().unwrap_err() {
        ControllerError::TooDeep { depth } => assert_eq!(depth, 33),
        other => panic!("expected TooDeep, got {other:?}"),
    }
    drop(client);
    mock.join();
}

#[test]
fn malformed_reply_is_a_protocol_error() {
    let mock = spawn_mock(vec![Step::Reply(b":xyz\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    assert!(matches!(
        client.node_list().unwrap_err(),
        ControllerError::Protocol(_)
    ));
    assert!(!client.is_connected());
    drop(client);
    mock.join();
}

// ============================================================================
// Transport failure semantics
// ============================================================================

#[test]
fn read_timeout_is_reported_and_marks_connection_dead() {
    let mock = spawn_mock(vec![Step::Hold]);
    let mut config = config_for(&mock.addr, Credentials::Unauthenticated);
    config.timeout = Duration::from_millis(200);
    let mut client = ControllerClient::connect(&config).unwrap();

    let start = std::time::Instant::now();
    let err = client.call(&[b"PING"]).unwrap_err();
    assert!(matches!(err, ControllerError::Timeout), "got {err:?}");
    assert!(start.elapsed() >= Duration::from_millis(150));
    assert!(!client.is_connected());
    // The dead connection fails fast on the next call without touching I/O.
    assert!(matches!(client.call(&[b"PING"]).unwrap_err(), ControllerError::Closed));
    drop(client);
    mock.join();
}

#[test]
fn peer_close_mid_reply_is_reported_as_closed() {
    let mock = spawn_mock(vec![Step::Truncate(b"$10\r\nabc".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    assert!(matches!(
        client.node_list().unwrap_err(),
        ControllerError::Closed
    ));
    assert!(!client.is_connected());
    assert!(matches!(
        client.node_list().unwrap_err(),
        ControllerError::Closed
    ));
    mock.join();
}

#[test]
fn oversized_command_is_rejected_without_sending() {
    let mock = spawn_mock(vec![Step::Reply(OK.to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    let huge = vec![b'x'; 16 * 1024 * 1024];
    match client.call(&[b"SET", &huge]).unwrap_err() {
        ControllerError::CommandTooLarge { .. } => {}
        other => panic!("expected CommandTooLarge, got {other:?}"),
    }
    // The connection is untouched by a rejected outbound command.
    assert!(client.is_connected());
    assert_eq!(client.call(&[b"PING"]).unwrap(), Reply::Simple("OK".into()));
    assert_eq!(mock.recorded(), vec![vec![b"PING".to_vec()]]);
    drop(client);
    mock.join();
}

// ============================================================================
// Watch cursor semantics
// ============================================================================

#[test]
fn watch_lifecycle_tracks_delivered_and_acked_cursors() {
    let event = b"*4\r\n:12\r\n$10\r\nvm.created\r\n$4\r\nvm-1\r\n$7\r\nbin\x00dat\r\n".to_vec();
    let mock = spawn_mock(vec![
        Step::Reply(b":9\r\n".to_vec()),  // WATCH.OPEN -> id 9
        Step::Reply(event),               // WATCH.NEXT -> event at offset 12
        Step::Reply(b":0\r\n".to_vec()),  // WATCH.NEXT -> journal end
        Step::Reply(OK.to_vec()),         // WATCH.ACK 9 12
        Step::Reply(OK.to_vec()),         // WATCH.RESUME 9 5
    ]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    let mut watch = client.watch_open(Some("vm-")).unwrap();
    assert_eq!(watch.id(), 9);
    assert_eq!(watch.prefix(), Some("vm-"));
    assert_eq!(watch.delivered_cursor(), 0);
    assert_eq!(watch.acked_cursor(), 0);

    let ev = watch.next(&mut client).unwrap().expect("an event");
    assert_eq!(ev.offset(), 12);
    assert_eq!(ev.event_type(), "vm.created");
    assert_eq!(ev.resource_id(), "vm-1");
    assert_eq!(ev.payload(), b"bin\x00dat");
    assert_eq!(watch.delivered_cursor(), 12);
    assert_eq!(watch.acked_cursor(), 0); // delivery is not an ack

    assert!(watch.next(&mut client).unwrap().is_none());
    assert_eq!(watch.delivered_cursor(), 12); // end-of-journal moves nothing

    watch.ack(&mut client).unwrap();
    assert_eq!(watch.acked_cursor(), 12);

    watch.resume(&mut client, 5).unwrap();
    assert_eq!(watch.delivered_cursor(), 5);
    assert_eq!(watch.acked_cursor(), 5);

    let recorded = mock.recorded();
    assert_eq!(recorded[0], vec![b"FEDERATION".to_vec(), b"WATCH.OPEN".to_vec(), b"vm-".to_vec()]);
    assert_eq!(recorded[1], vec![b"FEDERATION".to_vec(), b"WATCH.NEXT".to_vec(), b"9".to_vec()]);
    assert_eq!(
        recorded[3],
        vec![b"FEDERATION".to_vec(), b"WATCH.ACK".to_vec(), b"9".to_vec(), b"12".to_vec()]
    );
    assert_eq!(
        recorded[4],
        vec![b"FEDERATION".to_vec(), b"WATCH.RESUME".to_vec(), b"9".to_vec(), b"5".to_vec()]
    );
    drop(client);
    mock.join();
}

#[test]
fn watch_reopen_resumes_from_last_acked_cursor() {
    let event = b"*4\r\n:8\r\n$10\r\nvm.created\r\n$4\r\nvm-1\r\n$2\r\nok\r\n".to_vec();
    let mock = spawn_mock(vec![
        Step::Reply(b":4\r\n".to_vec()),  // WATCH.OPEN -> id 4
        Step::Reply(event),               // WATCH.NEXT -> event at offset 8
        Step::Reply(OK.to_vec()),         // WATCH.ACK 4 8
        Step::Reply(b":40\r\n".to_vec()), // WATCH.OPEN after reconnect -> id 40
        Step::Reply(OK.to_vec()),         // WATCH.RESUME 40 8
    ]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    let mut watch = client.watch_open(None).unwrap();
    assert!(watch.next(&mut client).unwrap().is_some());
    watch.ack(&mut client).unwrap();
    assert_eq!(watch.acked_cursor(), 8);

    watch.reopen(&mut client).unwrap();
    assert_eq!(watch.id(), 40);
    assert_eq!(watch.acked_cursor(), 8); // resumes from acked, not delivered
    assert_eq!(watch.prefix(), None);

    let recorded = mock.recorded();
    assert_eq!(recorded[3], vec![b"FEDERATION".to_vec(), b"WATCH.OPEN".to_vec()]);
    assert_eq!(
        recorded[4],
        vec![b"FEDERATION".to_vec(), b"WATCH.RESUME".to_vec(), b"40".to_vec(), b"8".to_vec()]
    );
    drop(client);
    mock.join();
}

#[test]
fn watch_next_rejects_wrong_reply_shape() {
    let mock = spawn_mock(vec![Step::Reply(b"$3\r\nbad\r\n".to_vec())]);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();
    assert!(matches!(
        client.watch_next(1).unwrap_err(),
        ControllerError::UnexpectedReply { .. }
    ));
    drop(client);
    mock.join();
}

// ============================================================================
// Full command vocabulary (mirrors the C client surface)
// ============================================================================

type BoxedCall = Box<dyn FnOnce(&mut ControllerClient)>;

fn row(
    name: &'static str,
    argv: &[&[u8]],
    reply: &'static [u8],
    f: impl FnOnce(&mut ControllerClient) + 'static,
) -> (&'static str, Vec<Vec<u8>>, &'static [u8], BoxedCall) {
    (name, argv.iter().map(|a| a.to_vec()).collect(), reply, Box::new(f))
}

#[test]
fn command_vocabulary_matches_the_c_client() {
    let rows: Vec<(&'static str, Vec<Vec<u8>>, &'static [u8], BoxedCall)> = vec![
        // ── Node / trust ──
        row("node_list", &[b"FEDERATION", b"NODE.LIST"], INT_ONE, |c| {
            c.node_list().unwrap();
        }),
        row("node_get", &[b"FEDERATION", b"NODE.SHOW", b"node-1"], INT_ONE, |c| {
            c.node_get("node-1").unwrap();
        }),
        row("node_enroll", &[b"FEDERATION", b"NODE.ENROLL", b"hypervisor", b"hv-1", b"boot-1"], INT_ONE, |c| {
            c.node_enroll("hypervisor", "hv-1", "boot-1").unwrap();
        }),
        row("node_approve_default_epoch", &[b"FEDERATION", b"NODE.APPROVE", b"node-1"], INT_ONE, |c| {
            c.node_approve("node-1", 0).unwrap();
        }),
        row("node_approve_epoch", &[b"FEDERATION", b"NODE.APPROVE", b"node-1", b"9"], INT_ONE, |c| {
            c.node_approve("node-1", 9).unwrap();
        }),
        row("node_revoke", &[b"FEDERATION", b"NODE.REVOKE", b"node-1"], INT_ONE, |c| {
            c.node_revoke("node-1").unwrap();
        }),
        row("trust_set", &[b"FEDERATION", b"TRUST.SET", b"node-1", b"attested", b"verified"], INT_ONE, |c| {
            c.trust_set("node-1", "attested", "verified").unwrap();
        }),
        row("trust_states", &[b"FEDERATION", b"TRUST.STATES"], INT_ONE, |c| {
            c.trust_states().unwrap();
        }),
        row("trust_admission", &[b"FEDERATION", b"TRUST.ADMISSION", b"node-1"], INT_ONE, |c| {
            c.trust_admission("node-1").unwrap();
        }),
        // ── Namespaces / groups ──
        row("ns_register", &[b"FEDERATION", b"NS.REGISTER", b"ns-1", b"QUORUM"], INT_ONE, |c| {
            c.ns_register("ns-1", "QUORUM", None).unwrap();
        }),
        row("ns_register_authority", &[b"FEDERATION", b"NS.REGISTER", b"ns-1", b"CAUSAL", b"node-1"], INT_ONE, |c| {
            c.ns_register("ns-1", "CAUSAL", Some("node-1")).unwrap();
        }),
        row("ns_unregister", &[b"FEDERATION", b"NS.UNREGISTER", b"ns-1"], INT_ONE, |c| {
            c.ns_unregister("ns-1").unwrap();
        }),
        row("ns_list", &[b"FEDERATION", b"NS.LIST"], INT_ONE, |c| {
            c.ns_list().unwrap();
        }),
        row("ns_writable", &[b"FEDERATION", b"NS.WRITABLE", b"ns-1"], INT_ONE, |c| {
            assert_eq!(c.ns_writable("ns-1").unwrap(), true);
        }),
        row("manifest", &[b"FEDERATION", b"MANIFEST", b"ns-1"], INT_ONE, |c| {
            c.manifest("ns-1").unwrap();
        }),
        row("group_create_default", &[b"FEDERATION", b"GROUP.CREATE", b"g-1"], INT_ONE, |c| {
            c.group_create("g-1", None).unwrap();
        }),
        row("group_create", &[b"FEDERATION", b"GROUP.CREATE", b"g-1", b"CAUSAL"], INT_ONE, |c| {
            c.group_create("g-1", Some("CAUSAL")).unwrap();
        }),
        row("group_add_plain", &[b"FEDERATION", b"GROUP.ADD", b"g-1", b"node-2"], INT_ONE, |c| {
            c.group_add("g-1", "node-2", false, false).unwrap();
        }),
        row("group_add_voter", &[b"FEDERATION", b"GROUP.ADD", b"g-1", b"node-2", b"voter"], INT_ONE, |c| {
            c.group_add("g-1", "node-2", true, false).unwrap();
        }),
        row("group_add_voter_witness", &[b"FEDERATION", b"GROUP.ADD", b"g-1", b"node-2", b"voter", b"witness"], INT_ONE, |c| {
            c.group_add("g-1", "node-2", true, true).unwrap();
        }),
        row("group_remove", &[b"FEDERATION", b"GROUP.REMOVE", b"g-1", b"node-2"], INT_ONE, |c| {
            c.group_remove("g-1", "node-2").unwrap();
        }),
        row("group_show", &[b"FEDERATION", b"GROUP.SHOW", b"g-1"], INT_ONE, |c| {
            c.group_show("g-1").unwrap();
        }),
        row("group_list", &[b"FEDERATION", b"GROUP.LIST"], INT_ONE, |c| {
            c.group_list().unwrap();
        }),
        row("group_advance", &[b"FEDERATION", b"GROUP.ADVANCE", b"g-1"], INT_ONE, |c| {
            c.group_advance("g-1").unwrap();
        }),
        // ── Objects ──
        row("object_get", &[b"FEDERATION", b"OBJECT.GET", b"ns-1", b"vm-1"], INT_ONE, |c| {
            c.object_get("ns-1", "vm-1").unwrap();
        }),
        row("object_cas_create_only", &[b"FEDERATION", b"OBJECT.CAS", b"ns-1", b"vm-1", b"{}", b"0"], INT_ONE, |c| {
            assert!(c.object_cas("ns-1", "vm-1", b"{}", CasPrecondition::CreateOnly).unwrap());
        }),
        // ── Leases / epochs ──
        row("lease_acquire_default_expiry", &[b"FEDERATION", b"LEASE.ACQUIRE", b"ns-1", b"vm-1", b"3"], INT_ONE, |c| {
            c.lease_acquire("ns-1", "vm-1", 3, 0).unwrap();
        }),
        row("lease_acquire_expiry", &[b"FEDERATION", b"LEASE.ACQUIRE", b"ns-1", b"vm-1", b"3", b"9000"], INT_ONE, |c| {
            c.lease_acquire("ns-1", "vm-1", 3, 9000).unwrap();
        }),
        row("lease_read", &[b"FEDERATION", b"LEASE.READ", b"lease-9"], INT_ONE, |c| {
            c.lease_read("lease-9").unwrap();
        }),
        row("lease_renew", &[b"FEDERATION", b"LEASE.RENEW", b"lease-9", b"60000"], INT_ONE, |c| {
            c.lease_renew("lease-9", 60000).unwrap();
        }),
        row("lease_release", &[b"FEDERATION", b"LEASE.RELEASE", b"lease-9"], INT_ONE, |c| {
            c.lease_release("lease-9").unwrap();
        }),
        row("epoch_next", &[b"FEDERATION", b"EPOCH.NEXT"], INT_ONE, |c| {
            assert_eq!(c.epoch_next().unwrap(), 1u64);
        }),
        row("epoch_current", &[b"FEDERATION", b"EPOCH.CURRENT"], INT_ONE, |c| {
            assert_eq!(c.epoch_current().unwrap(), 1u64);
        }),
        // ── Events ──
        row("event_append_no_payload", &[b"FEDERATION", b"EVENT.APPEND", b"vm.created", b"vm-1"], INT_ONE, |c| {
            assert_eq!(c.event_append("vm.created", "vm-1", None).unwrap(), 1u64);
        }),
        row("event_replay", &[b"FEDERATION", b"EVENT.REPLAY", b"0"], INT_ONE, |c| {
            c.event_replay(0).unwrap();
        }),
        row("event_replay_cursor", &[b"FEDERATION", b"EVENT.REPLAY", b"77"], INT_ONE, |c| {
            c.event_replay(77).unwrap();
        }),
        // ── Watches (raw client surface) ──
        row("watch_open_all", &[b"FEDERATION", b"WATCH.OPEN"], INT_ONE, |c| {
            let w = c.watch_open(None).unwrap();
            assert_eq!(w.id(), 1);
        }),
        row("watch_open_prefix", &[b"FEDERATION", b"WATCH.OPEN", b"vm-"], b":2\r\n", |c| {
            let w = c.watch_open(Some("vm-")).unwrap();
            assert_eq!((w.id(), w.prefix()), (2, Some("vm-")));
        }),
        row("watch_next_end", &[b"FEDERATION", b"WATCH.NEXT", b"2"], b":0\r\n", |c| {
            assert!(c.watch_next(2).unwrap().is_none());
        }),
        row("watch_ack", &[b"FEDERATION", b"WATCH.ACK", b"2", b"8"], OK, |c| {
            c.watch_ack(2, 8).unwrap();
        }),
        row("watch_resume", &[b"FEDERATION", b"WATCH.RESUME", b"2", b"5"], OK, |c| {
            c.watch_resume(2, 5).unwrap();
        }),
        // ── Conflicts / status ──
        row("conflict_list", &[b"FEDERATION", b"CONFLICT.LIST"], INT_ONE, |c| {
            c.conflict_list().unwrap();
        }),
        row("conflict_resolve", &[b"FEDERATION", b"CONFLICT.RESOLVE", b"c-1", b"node-1"], INT_ONE, |c| {
            c.conflict_resolve("c-1", "node-1").unwrap();
        }),
        row("federation_status", &[b"FEDERATION", b"STATUS"], INT_ONE, |c| {
            c.federation_status().unwrap();
        }),
        row("rejoin_status", &[b"FEDERATION", b"REJOIN.STATUS", b"node-1"], INT_ONE, |c| {
            c.rejoin_status("node-1").unwrap();
        }),
        row("metrics_all", &[b"FEDERATION", b"METRICS"], INT_ONE, |c| {
            c.metrics(None).unwrap();
        }),
        row("metrics_prefix", &[b"FEDERATION", b"METRICS", b"fed"], INT_ONE, |c| {
            c.metrics(Some("fed")).unwrap();
        }),
        // ── Build coordination ──
        row("build_job_create", &[b"FEDERATION", b"BUILD.CREATE", b"qihse", b"rev-1", b"release", b"gnu"], INT_ONE, |c| {
            c.build_job_create("qihse", "rev-1", "release", "gnu").unwrap();
        }),
        row("build_job_transition", &[b"FEDERATION", b"BUILD.TRANSITION", b"b-1", b"RUNNING", b"req-1"], INT_ONE, |c| {
            c.build_job_transition("b-1", "RUNNING", "req-1", None).unwrap();
        }),
        row("build_job_transition_reason", &[b"FEDERATION", b"BUILD.TRANSITION", b"b-1", b"DONE", b"req-2", b"cache hit"], INT_ONE, |c| {
            c.build_job_transition("b-1", "DONE", "req-2", Some("cache hit")).unwrap();
        }),
        row("build_job_get", &[b"FEDERATION", b"BUILD.SHOW", b"b-1"], INT_ONE, |c| {
            c.build_job_get("b-1").unwrap();
        }),
        row("build_job_list", &[b"FEDERATION", b"BUILD.LIST"], INT_ONE, |c| {
            c.build_job_list().unwrap();
        }),
        row("build_states", &[b"FEDERATION", b"BUILD.STATES"], INT_ONE, |c| {
            c.build_states().unwrap();
        }),
        row("build_worker_publish", &[b"FEDERATION", b"BUILDER.CAP", b"node-1", b"8", b"32", b"0"], INT_ONE, |c| {
            c.build_worker_publish("node-1", 8, 32, 0).unwrap();
        }),
        row("build_worker_get", &[b"FEDERATION", b"BUILDER.SHOW", b"node-1"], INT_ONE, |c| {
            c.build_worker_get("node-1").unwrap();
        }),
        // ── Supply chain ──
        row("pkg_set", &[b"FEDERATION", b"PKG.SET", b"qihse", b"ALLOW", b"pinned"], INT_ONE, |c| {
            c.pkg_set("qihse", "ALLOW", "pinned").unwrap();
        }),
        row("pkg_get", &[b"FEDERATION", b"PKG.GET", b"qihse"], INT_ONE, |c| {
            c.pkg_get("qihse").unwrap();
        }),
        row("pkg_modes", &[b"FEDERATION", b"PKG.MODES"], INT_ONE, |c| {
            c.pkg_modes().unwrap();
        }),
        row("supply_sbom", &[b"FEDERATION", b"SUPPLY.SBOM", b"sha:a", b"sha:b", b"signer-1", b"cyclonedx"], INT_ONE, |c| {
            c.supply_sbom("sha:a", "sha:b", "signer-1", "cyclonedx").unwrap();
        }),
        row("supply_sbom_get", &[b"FEDERATION", b"SUPPLY.SBOM.GET", b"sha:b"], INT_ONE, |c| {
            c.supply_sbom_get("sha:b").unwrap();
        }),
        row("supply_snapshot_no_count", &[b"FEDERATION", b"SUPPLY.SNAPSHOT", b"main", b"sha:c", b"rel-1"], INT_ONE, |c| {
            c.supply_snapshot("main", "sha:c", "rel-1", 0).unwrap();
        }),
        row("supply_snapshot_count", &[b"FEDERATION", b"SUPPLY.SNAPSHOT", b"main", b"sha:c", b"rel-1", b"12"], INT_ONE, |c| {
            c.supply_snapshot("main", "sha:c", "rel-1", 12).unwrap();
        }),
        row("supply_snapshot_list_all", &[b"FEDERATION", b"SUPPLY.SNAPSHOT.LIST"], INT_ONE, |c| {
            c.supply_snapshot_list(None).unwrap();
        }),
        row("supply_snapshot_list_repo", &[b"FEDERATION", b"SUPPLY.SNAPSHOT.LIST", b"main"], INT_ONE, |c| {
            c.supply_snapshot_list(Some("main")).unwrap();
        }),
        row("supply_vuln", &[b"FEDERATION", b"SUPPLY.VULN", b"sha:d", b"CVE-2026-1234", b"high", b"open"], INT_ONE, |c| {
            c.supply_vuln("sha:d", "CVE-2026-1234", "high", "open").unwrap();
        }),
        row("supply_vuln_count", &[b"FEDERATION", b"SUPPLY.VULN.COUNT", b"sha:d"], INT_ONE, |c| {
            c.supply_vuln_count("sha:d").unwrap();
        }),
        // ── Provenance ──
        row("prov_node", &[b"FEDERATION", b"PROV.NODE", b"artifact", b"sha:a"], INT_ONE, |c| {
            c.prov_node("artifact", "sha:a", None).unwrap();
        }),
        row("prov_node_label", &[b"FEDERATION", b"PROV.NODE", b"artifact", b"sha:a", b"built-by"], INT_ONE, |c| {
            c.prov_node("artifact", "sha:a", Some("built-by")).unwrap();
        }),
        row("prov_edge", &[b"FEDERATION", b"PROV.EDGE", b"artifact:sha:a", b"BUILT_AS", b"build:9"], INT_ONE, |c| {
            c.prov_edge("artifact:sha:a", "BUILT_AS", "build:9").unwrap();
        }),
        row("prov_show", &[b"FEDERATION", b"PROV.SHOW", b"artifact", b"sha:a"], INT_ONE, |c| {
            c.prov_show("artifact", "sha:a").unwrap();
        }),
        row("prov_trace_forward_default_depth", &[b"FEDERATION", b"PROV.TRACE", b"artifact", b"sha:a", b"forward"], INT_ONE, |c| {
            c.prov_trace("artifact", "sha:a", true, 0).unwrap();
        }),
        row("prov_trace_reverse_depth", &[b"FEDERATION", b"PROV.TRACE", b"artifact", b"sha:a", b"reverse", b"4"], INT_ONE, |c| {
            c.prov_trace("artifact", "sha:a", false, 4).unwrap();
        }),
        row("prov_impact_default_depth", &[b"FEDERATION", b"PROV.IMPACT", b"artifact", b"sha:a", b"service"], INT_ONE, |c| {
            c.prov_impact("artifact", "sha:a", "service", 0).unwrap();
        }),
        row("prov_impact_depth", &[b"FEDERATION", b"PROV.IMPACT", b"artifact", b"sha:a", b"service", b"2"], INT_ONE, |c| {
            c.prov_impact("artifact", "sha:a", "service", 2).unwrap();
        }),
        // ── Snapshots ──
        row("snapshot_create_unencrypted", &[b"FEDERATION", b"SNAPSHOT.CREATE", b"local", b"100", b"5000"], INT_ONE, |c| {
            c.snapshot_create("local", 100, 5000, None).unwrap();
        }),
        row("snapshot_create_key", &[b"FEDERATION", b"SNAPSHOT.CREATE", b"coordinated", b"100", b"5000", b"kms-1"], INT_ONE, |c| {
            c.snapshot_create("coordinated", 100, 5000, Some("kms-1")).unwrap();
        }),
        row("snapshot_show", &[b"FEDERATION", b"SNAPSHOT.SHOW", b"snap-1"], INT_ONE, |c| {
            c.snapshot_show("snap-1").unwrap();
        }),
        row("snapshot_verify", &[b"FEDERATION", b"SNAPSHOT.VERIFY", b"snap-1"], INT_ONE, |c| {
            c.snapshot_verify("snap-1").unwrap();
        }),
        // ── Schema evolution ──
        row("schema_status", &[b"FEDERATION", b"SCHEMA.STATUS", b"sc-1", b"2"], INT_ONE, |c| {
            c.schema_status("sc-1", "2").unwrap();
        }),
        row("schema_check", &[b"FEDERATION", b"SCHEMA.CHECK", b"3", b"1", b"01", b"02"], INT_ONE, |c| {
            c.schema_check("3", "1", "01", "02").unwrap();
        }),
        row("schema_migrate_resumable", &[b"FEDERATION", b"SCHEMA.MIGRATE", b"sc-1", b"1", b"2", b"1"], INT_ONE, |c| {
            c.schema_migrate("sc-1", "1", "2", true).unwrap();
        }),
        row("schema_migrate_non_resumable", &[b"FEDERATION", b"SCHEMA.MIGRATE", b"sc-1", b"1", b"2", b"0"], INT_ONE, |c| {
            c.schema_migrate("sc-1", "1", "2", false).unwrap();
        }),
        row("schema_progress", &[b"FEDERATION", b"SCHEMA.PROGRESS", b"sc-1", b"2", b"10", b"100"], INT_ONE, |c| {
            c.schema_progress("sc-1", "2", 10, 100).unwrap();
        }),
        // ── Security posture ──
        row("security_audit_all", &[b"FEDERATION", b"SECURITY.AUDIT"], INT_ONE, |c| {
            c.security_audit(None, None).unwrap();
        }),
        row("security_audit_service", &[b"FEDERATION", b"SECURITY.AUDIT", b"qihse"], INT_ONE, |c| {
            c.security_audit(Some("qihse"), None).unwrap();
        }),
        row("security_audit_service_version", &[b"FEDERATION", b"SECURITY.AUDIT", b"qihse", b"1.2"], INT_ONE, |c| {
            c.security_audit(Some("qihse"), Some("1.2")).unwrap();
        }),
        row("security_observe", &[b"FEDERATION", b"SECURITY.OBSERVE"], INT_ONE, |c| {
            c.security_observe().unwrap();
        }),
        row("security_ifaces", &[b"FEDERATION", b"SECURITY.IFACES"], INT_ONE, |c| {
            c.security_ifaces().unwrap();
        }),
        row("security_profile_get", &[b"FEDERATION", b"SECURITY.PROFILE.GET", b"qihse", b"1.2"], INT_ONE, |c| {
            c.security_profile_get("qihse", "1.2").unwrap();
        }),
        row("security_net_get", &[b"FEDERATION", b"SECURITY.NET.GET", b"qihse", b"1.2"], INT_ONE, |c| {
            c.security_net_get("qihse", "1.2").unwrap();
        }),
    ];

    let script = rows
        .iter()
        .map(|(_, _, reply, _)| Step::Reply(reply.to_vec()))
        .collect();
    let expected: Vec<(&'static str, Vec<Vec<u8>>)> =
        rows.iter().map(|(n, argv, _, _)| (*n, argv.clone())).collect();
    let mock = spawn_mock(script);
    let mut client =
        ControllerClient::connect(&config_for(&mock.addr, Credentials::Unauthenticated)).unwrap();

    for (_, _, _, call) in rows {
        call(&mut client); // each closure asserts its own typed result
    }

    let recorded = mock.recorded();
    assert_eq!(recorded.len(), expected.len(), "one round-trip per wrapper");
    for (i, (name, exp)) in expected.iter().enumerate() {
        assert_eq!(&recorded[i], exp, "wire mismatch for {name}");
    }
    drop(client);
    mock.join();
}
