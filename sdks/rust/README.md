# Rust PostgreSQL wire SDK

`Config::connect(connector)` forwards a standard
`tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket>` connector.
TLS is required by default; negotiation, certificate or authentication failures
never retry in plaintext. Configure certificate-chain and hostname verification
in the connector. For example, with `native-tls` and `postgres-native-tls`:

```rust,ignore
let ca = native_tls::Certificate::from_pem(&std::fs::read("ca.pem")?)?;
let mut tls = native_tls::TlsConnector::builder();
tls.add_root_certificate(ca);
let connector = postgres_native_tls::MakeTlsConnector::new(tls.build()?);
let (client, connection) = qihse_rust::Config::new()
    .host("db.example.com").user("User_2").password("password")
    .connect(connector).await?;
tokio::spawn(connection);
```

Migration: callers intentionally using plaintext must now explicitly use
`Config::new().disable_tls().connect(qihse_rust::NoTls)`. This transmits credentials
and data unencrypted; it is not a fallback for TLS errors. Existing builder and
connection return types are unchanged. The connector is no longer ignored, so
arbitrary non-connector marker arguments are no longer accepted.

Run unit/protocol tests with `cargo test --locked --manifest-path sdks/rust/Cargo.toml`.
After building `libqihse.so`, run real TLS and authorization integration from the
repository root with `python3 -m pytest -q sdks/rust/tests/test_tls.py`.
The harness reuses the shared disposable authenticated TLS server, generates an
unrelated CA, and runs the otherwise ignored Rust integration test. It never
