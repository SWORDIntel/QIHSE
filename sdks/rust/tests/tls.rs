//! Real-server test is launched by tests/test_tls.py with a disposable fixture.
use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use qihse_rust::{Config, NoTls, SimpleQueryMessage};
use std::{env, fs, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_postgres::{tls::MakeTlsConnect, Socket};

fn connector(ca: Option<&str>) -> MakeTlsConnector {
    let mut builder = TlsConnector::builder();
    builder.disable_built_in_roots(true);
    if let Some(ca) = ca {
        builder.add_root_certificate(Certificate::from_pem(&fs::read(ca).unwrap()).unwrap());
    }
    MakeTlsConnector::new(builder.build().unwrap())
}

fn assert_authorization_denial(error: std::io::Error) {
    assert!(!error.to_string().contains("DIRECTEYE-HIGH-SECRET-MARKER"));
    let pg = error.get_ref().unwrap().downcast_ref::<tokio_postgres::Error>().unwrap();
    assert_eq!(pg.as_db_error().unwrap().code().code(), "42501");
}

// Verify a mismatched certificate name independently of TCP routing.
struct WrongHostname(MakeTlsConnector);
impl MakeTlsConnect<Socket> for WrongHostname {
    type Stream = <MakeTlsConnector as MakeTlsConnect<Socket>>::Stream;
    type TlsConnect = <MakeTlsConnector as MakeTlsConnect<Socket>>::TlsConnect;
    type Error = <MakeTlsConnector as MakeTlsConnect<Socket>>::Error;

    fn make_tls_connect(&mut self, _: &str) -> Result<Self::TlsConnect, Self::Error> {
        <MakeTlsConnector as MakeTlsConnect<Socket>>::make_tls_connect(
            &mut self.0, "not-the-fixture.invalid",
        )
    }
}

#[tokio::test]
async fn tls_refusal_never_sends_startup_or_credentials() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 8];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
        socket.write_all(b"N").await.unwrap();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
    });
    let result = Config::new().host("127.0.0.1").port(port)
        .user("secret-user").password("secret-password").connect(connector(None)).await;
    assert!(result.is_err(), "TLS refusal must fail instead of downgrading");
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
}

#[tokio::test]
async fn plaintext_requires_explicit_opt_in() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let length = socket.read_u32().await.unwrap();
        assert!(length > 8 && length < 4096, "expected startup, not SSLRequest");
        let mut startup = vec![0; length as usize - 4];
        socket.read_exact(&mut startup).await.unwrap();
        assert_eq!(&startup[..4], &[0, 3, 0, 0]);
        // AuthenticationOk followed by ReadyForQuery.
        socket.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").await.unwrap();
        let mut terminated = [0; 5];
        let _ = socket.read(&mut terminated).await;
    });
    let (client, connection) = Config::new().host("127.0.0.1").port(port)
        .disable_tls().connect(NoTls).await.unwrap();
    assert!(client.is_authenticated().await);
    drop(client);
    drop(connection);
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
}

#[tokio::test]
#[ignore = "requires disposable server; run pytest sdks/rust/tests/test_tls.py"]
async fn verified_tls_and_principal_authorization() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let ca = env::var("QIHSE_RUST_TLS_CA").unwrap();
        let config = |user: &str| Config::new().host("127.0.0.1")
            .port(env::var("QIHSE_RUST_TLS_PORT").unwrap().parse().unwrap())
            .dbname("qihse").user(user).password(&env::var("QIHSE_RUST_TLS_PASSWORD").unwrap());
        let operator = env::var("QIHSE_RUST_TLS_USER").unwrap();
        let guest = env::var("QIHSE_RUST_TLS_GUEST").unwrap();

        let wrong_ca = env::var("QIHSE_RUST_TLS_WRONG_CA").unwrap();
        assert!(config(&operator).connect(connector(Some(&wrong_ca))).await.is_err(), "wrong CA accepted");
        assert!(config(&operator).connect(WrongHostname(connector(Some(&ca)))).await.is_err(),
            "wrong hostname accepted");
        assert!(config(&operator).connect(NoTls).await.is_err(), "NoTls bypassed required TLS");
        assert!(config(&operator).password("wrong-password").connect(connector(Some(&ca))).await.is_err(),
            "TLS bypassed principal authentication");

        let (client, connection) = config(&operator).connect(connector(Some(&ca))).await.unwrap();
        let driver = tokio::spawn(connection);
        assert!(client.is_authenticated().await);
        let rows = client.simple_query("SELECT note FROM protected_records WHERE id = 7").await.unwrap();
        assert!(rows.iter().any(|row| matches!(row, SimpleQueryMessage::Row(row)
            if row.get(0) == Some("DIRECTEYE-HIGH-SECRET-MARKER"))));
        drop(client);
        driver.await.unwrap().unwrap();

        let (client, connection) = config(&guest).connect(connector(Some(&ca))).await.unwrap();
        let driver = tokio::spawn(connection);
        assert!(client.is_authenticated().await);
        for sql in ["SELECT note FROM protected_records", "SELECT note FROM protected_records WHERE id = 7"] {
            match client.simple_query(sql).await {
                Ok(messages) => assert!(!messages.iter().any(|m| matches!(m, SimpleQueryMessage::Row(_))),
                    "low-clearance principal received protected rows"),
                Err(error) => assert_authorization_denial(error),
            }
        }
        for sql in ["SELECT note FROM protected_records", "SELECT note FROM protected_records WHERE id = 7"] {
            match client.query(sql, &[]).await {
                Ok(rows) => assert!(rows.is_empty(), "extended query disclosed protected rows"),
                Err(error) => assert_authorization_denial(error),
            }
        }
        drop(client);
        driver.await.unwrap().unwrap();
    }).await.expect("TLS integration timed out");
}
