//! Standalone integration tests: `rustc --edition=2021 --test tests/python_remote.rs`.
//! The crate root does not yet export python_remote (outside this task's scope).
#[path = "../src/controller.rs"]
mod controller;
#[path = "../src/python_remote.rs"]
mod python_remote;

use controller::{ControllerConfig, ControllerError, Credentials};
use python_remote::{AIMEMClient, RecallMode, Scope};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn line(sock: &mut TcpStream) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut b = [0];
        sock.read_exact(&mut b).expect("command line");
        if b[0] == b'\n' {
            assert_eq!(result.pop(), Some(b'\r'));
            return result;
        }
        result.push(b[0]);
        assert!(result.len() < 128, "unexpectedly large command header");
    }
}

fn command(sock: &mut TcpStream) -> Vec<Vec<u8>> {
    let header = line(sock);
    let count: usize = std::str::from_utf8(&header[1..]).unwrap().parse().unwrap();
    assert_eq!(header[0], b'*');
    (0..count).map(|_| {
        let header = line(sock);
        assert_eq!(header[0], b'$');
        let size: usize = std::str::from_utf8(&header[1..]).unwrap().parse().unwrap();
        let mut data = vec![0; size];
        sock.read_exact(&mut data).unwrap();
        let mut tail = [0; 2];
        sock.read_exact(&mut tail).unwrap();
        assert_eq!(tail, *b"\r\n");
        data
    }).collect()
}

fn mock(responses: &[&[u8]]) -> (ControllerConfig, mpsc::Receiver<Vec<Vec<u8>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let replies: Vec<_> = responses.iter().map(|s| s.to_vec()).collect();
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        for response in replies {
            let cmd = command(&mut sock);
            let _ = tx.send(cmd);
            sock.write_all(&response).unwrap();
        }
    });
    let mut cfg = ControllerConfig::new("127.0.0.1", port, Credentials::Password {
        username: "low-user".into(), password: "explicit-secret".into(),
    });
    cfg.timeout = Duration::from_millis(250);
    (cfg, rx, handle)
}

fn scope() -> Scope { Scope::new("project", "worktree", "stream", "session").unwrap() }
fn bytes(command: &[Vec<u8>]) -> Vec<&[u8]> { command.iter().map(Vec::as_slice).collect() }
macro_rules! assert_command {
    ($cmd:expr, $($arg:expr),+ $(,)?) => {{
        let expected: Vec<&[u8]> = vec![$($arg.as_ref()),+];
        assert_eq!(bytes($cmd), expected);
    }};
}

#[test]
fn scope_and_transport_fail_closed_before_connect() {
    assert!(Scope::new("", "", "", "").is_err());
    assert!(Scope::new("p", "", "stream", "").is_err());
    assert!(Scope::new("p", "tree", "", "session").is_err());
    assert!(Scope::new("p/escape", "", "", "").is_err());
    assert!(Scope::new("p", "x".repeat(64).as_str(), "", "").is_err());
    let cfg = ControllerConfig::new("127.0.0.1", 1, Credentials::Unauthenticated);
    assert!(matches!(AIMEMClient::connect(&cfg, scope()), Err(ControllerError::InvalidConfig(_))));
    let cfg = ControllerConfig::new("localhost", 1, Credentials::Password {username:"u".into(),password:"p".into()});
    assert!(matches!(AIMEMClient::connect(&cfg, scope()), Err(ControllerError::InvalidConfig(_))));
    let cfg = ControllerConfig::new("203.0.113.2", 1, Credentials::Password {username:"u".into(),password:"p".into()});
    assert!(matches!(AIMEMClient::connect(&cfg, scope()), Err(ControllerError::InvalidConfig(_))));
}

#[test]
fn scoped_memory_wire_and_parsing() {
    let hit = b"*7\r\n$2\r\nm1\r\n$2\r\n42\r\n$1\r\n1\r\n$1\r\n3\r\n$1\r\n2\r\n$3\r\n0.5\r\n$5\r\nhello\r\n";
    let recall = [&b"*1\r\n"[..], hit].concat();
    let (cfg, rx, handle) = mock(&[b"+OK\r\n", b"$2\r\nm1\r\n", b"*4\r\n$12\r\nSTORE-SCOPED\r\n$2\r\nm1\r\n$5\r\ntoken\r\n$11\r\nlocal-fsync\r\n", &recall, hit, b":5\r\n", b":1\r\n", b"$-1\r\n"]);
    let mut client = AIMEMClient::connect(&cfg, scope()).unwrap();
    assert_eq!(client.store(1, "hello\r\n", Some("retry-1"), false).unwrap(), "m1");
    let r = client.store_receipt(2, "world", "retry-2").unwrap();
    assert_eq!((r.id.as_str(), r.token.as_str(), r.durability.as_str()), ("m1", "token", "local-fsync"));
    let hits = client.recall("hello", 10, RecallMode::Hybrid, 0).unwrap();
    assert_eq!((hits[0].classification, hits[0].sci_compartment, hits[0].score), (3, 2, 0.5));
    assert_eq!(client.get("m1").unwrap().unwrap().text, "hello");
    assert_eq!(client.count(0).unwrap(), 5);
    assert!(client.forget("m1", true).unwrap());
    assert!(client.event_get("missing").unwrap().is_none());
    let cmds: Vec<_> = rx.try_iter().collect();
    assert_command!(&cmds[0], b"AUTH", b"low-user", b"explicit-secret");
    assert_command!(&cmds[1], b"AIMEM", b"STORE-SCOPED", b"1", b"hello\r\n", b"project", b"worktree", b"stream", b"session", b"retry-1");
    assert_command!(&cmds[2], b"AIMEM", b"STORE-SCOPED-RECEIPT", b"2", b"world", b"project", b"worktree", b"stream", b"session", b"retry-2");
    assert_command!(&cmds[3], b"AIMEM", b"RECALL-SCOPED", b"hello", b"10", b"hybrid", b"0", b"project", b"worktree", b"stream", b"session");
    assert_command!(&cmds[4], b"AIMEM", b"GET-SCOPED", b"m1", b"project", b"worktree", b"stream", b"session");
    assert_command!(&cmds[5], b"AIMEM", b"COUNT-SCOPED", b"project", b"worktree", b"stream", b"session", b"0");
    assert_eq!(bytes(&cmds[6])[1], b"FORGET-SCOPED-DURABLE");
    assert_eq!(&bytes(&cmds[7])[..3], &[&b"AIMEM"[..], &b"EVENT"[..], &b"READ"[..]]);
    drop(client);
    handle.join().unwrap();
}

#[test]
fn denied_low_clearance_read_never_returns_high_payload() {
    // Mock wire denial pins propagation/no fallback; only a live server test
    // can establish that high-classification records are actually withheld.
    let (cfg, rx, handle) = mock(&[b"+OK\r\n", b"-NOPERM clearance below protected item\r\n", b"-NOPERM clearance below protected item\r\n"]);
    let mut client = AIMEMClient::connect(&cfg, scope()).unwrap();
    for result in [client.recall("secret", 1, RecallMode::Bm25, 0).map(|_| ()), client.get("high-id").map(|_| ())] {
        match result { Err(ControllerError::Server { class, message }) => {
            assert_eq!(class, "NOPERM");
            assert!(!message.contains("HIGH_PAYLOAD"));
        }, other => panic!("expected denial, got {other:?}") }
    }
    let cmds: Vec<_> = rx.try_iter().collect();
    assert_eq!(bytes(&cmds[1])[1], b"RECALL-SCOPED");
    assert_eq!(bytes(&cmds[2])[1], b"GET-SCOPED");
    drop(client);
    handle.join().unwrap();
}

#[test]
fn event_and_forget_receipt_preserve_positional_fields() {
    let (cfg, rx, handle) = mock(&[b"+OK\r\n", b"$7\r\nevent-1\r\n", b"*4\r\n$13\r\nFORGET-SCOPED\r\n$2\r\nm1\r\n$3\r\nack\r\n$11\r\nlocal-fsync\r\n"]);
    let mut client = AIMEMClient::connect(&cfg, scope()).unwrap();
    assert_eq!(client.event_append("agent", "event-key", "decision", 42, "done", Some("evidence")).unwrap(), "event-1");
    assert_eq!(client.forget_receipt("m1", "retry").unwrap().operation, "FORGET-SCOPED");
    let cmds: Vec<_> = rx.try_iter().collect();
    assert_command!(&cmds[1], b"AIMEM", b"EVENT", b"APPEND", b"project", b"worktree", b"stream", b"session", b"agent", b"event-key", b"decision", b"42", b"done", b"evidence");
    assert_command!(&cmds[2], b"AIMEM", b"FORGET-SCOPED-RECEIPT", b"m1", b"project", b"worktree", b"stream", b"session", b"retry");
    drop(client);
    handle.join().unwrap();
}

#[test]
fn refused_auth_never_sends_aimem() {
    let (cfg, rx, handle) = mock(&[b"-NOAUTH invalid credentials\r\n"]);
    match AIMEMClient::connect(&cfg, scope()) {
        Err(ControllerError::Server { class, .. }) => assert_eq!(class, "NOAUTH"),
        _ => panic!("expected AUTH refusal"),
    }
    handle.join().unwrap();
    let commands: Vec<_> = rx.try_iter().collect();
    assert_eq!(commands.len(), 1);
    assert_eq!(bytes(&commands[0])[0], b"AUTH");
}

#[test]
fn invalid_shape_and_server_denial_are_not_fabricated_as_success() {
    let (cfg, _, handle) = mock(&[b"+OK\r\n", b":2\r\n", b"*1\r\n+bad\r\n"]);
    let mut client = AIMEMClient::connect(&cfg, scope()).unwrap();
    assert!(matches!(client.forget("x", false), Err(ControllerError::UnexpectedReply { .. })));
    assert!(matches!(client.recall("x", 1, RecallMode::Semantic, 0), Err(ControllerError::UnexpectedReply { .. })));
    drop(client);
    handle.join().unwrap();
}
