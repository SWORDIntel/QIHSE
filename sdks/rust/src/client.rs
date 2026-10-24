//! PostgreSQL wire client and small async API compatible with the SDK surface.

use crate::error::{target, AuthState, UwpError};
use crate::query::{Row, SimpleQueryMessage, SimpleQueryRow};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_postgres::types::ToSql;

/// Marker retained for callers that do not configure TLS.
///
/// The current QIHSE PostgreSQL listener does not offer TLS negotiation. The
/// credentials and SQL traffic therefore use the listener's configured
/// transport; use a protected network when connecting with this marker.
pub struct NoTls;

/// Connection configuration builder.
pub struct Config {
    host: String,
    port: u16,
    dbname: String,
    user: String,
    password: String,
}

impl Config {
    pub fn new() -> Self {
        Self {
            host: "localhost".into(),
            port: 5432,
            dbname: "test".into(),
            user: "admin".into(),
            password: String::new(),
        }
    }
    pub fn host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    pub fn dbname(mut self, dbname: &str) -> Self {
        self.dbname = dbname.to_string();
        self
    }
    pub fn user(mut self, user: &str) -> Self {
        self.user = user.to_string();
        self
    }
    pub fn password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    /// Connect and authenticate using the configured database principal.
    ///
    /// Authentication completes during the PostgreSQL startup handshake. A
    /// returned client is considered authenticated only after that succeeds.
    pub async fn connect<T>(&self, _tls: T) -> io::Result<(Client, Connection)>
    where
        T: Send + 'static,
    {
        let mut pg = tokio_postgres::Config::new();
        pg.host(&self.host)
            .port(self.port)
            .dbname(&self.dbname)
            .user(&self.user)
            .password(&self.password);
        let (client, connection) = pg.connect(tokio_postgres::NoTls).await.map_err(pg_error)?;
        let task: Pin<Box<dyn Future<Output = io::Result<()>> + Send>> =
            Box::pin(async move { connection.await.map_err(pg_error) });
        let inner = Arc::new(Mutex::new(ClientInner {
            client: Some(Arc::new(client)),
            closed: false,
            auth_state: AuthState::Authenticated,
        }));
        Ok((Client { inner }, Connection { task }))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Database client. Calls are serialized on the underlying connection.
pub struct Client {
    inner: Arc<Mutex<ClientInner>>,
}

struct ClientInner {
    client: Option<Arc<tokio_postgres::Client>>,
    closed: bool,
    auth_state: AuthState,
}

impl Client {
    /// Create a disconnected client. Use [`Config::connect`] for a usable one.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ClientInner {
                client: None,
                closed: false,
                auth_state: AuthState::Unauthenticated,
            })),
        }
    }

    /// Authentication is performed at connect time with the configured user.
    /// This method refuses to turn a disconnected client into an authenticated
    /// one without a server handshake.
    pub async fn authenticate(&self, _username: &str, _password: &str) -> Result<(), UwpError> {
        let inner = self.inner.lock().await;
        if inner.client.is_some() && inner.auth_state == AuthState::Authenticated {
            Ok(())
        } else {
            Err(UwpError::Auth(
                "connect with Config credentials before issuing SQL".into(),
            ))
        }
    }

    pub async fn is_authenticated(&self) -> bool {
        self.inner.lock().await.auth_state == AuthState::Authenticated
    }

    async fn pg_client(&self) -> io::Result<Arc<tokio_postgres::Client>> {
        let inner = self.inner.lock().await;
        inner
            .auth_state
            .check(target::SQL)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        if inner.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "client is closed",
            ));
        }
        inner
            .client
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "client is not connected"))
    }

    pub async fn simple_query(&self, query: &str) -> io::Result<Vec<SimpleQueryMessage>> {
        self.pg_client()
            .await?
            .simple_query(query)
            .await
            .map(|messages| {
                messages
                    .into_iter()
                    .filter_map(|m| match m {
                        tokio_postgres::SimpleQueryMessage::Row(row) => Some({
                            let values = (0..row.len())
                                .map(|i| row.get(i).map(str::to_owned))
                                .collect();
                            SimpleQueryMessage::Row(SimpleQueryRow::new(values))
                        }),
                        tokio_postgres::SimpleQueryMessage::CommandComplete(n) => {
                            Some(SimpleQueryMessage::CommandComplete(n))
                        }
                        tokio_postgres::SimpleQueryMessage::RowDescription(_) => None,
                        _ => None,
                    })
                    .collect()
            })
            .map_err(pg_error)
    }

    pub async fn query(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> io::Result<Vec<Row>> {
        self.pg_client()
            .await?
            .query(query, params)
            .await
            .map_err(pg_error)
    }

    pub async fn execute(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> io::Result<u64> {
        self.pg_client()
            .await?
            .execute(query, params)
            .await
            .map_err(pg_error)
    }

    pub async fn batch_execute(&self, query: &str) -> io::Result<()> {
        self.pg_client()
            .await?
            .batch_execute(query)
            .await
            .map_err(pg_error)
    }

    pub async fn transaction(&self) -> io::Result<Transaction> {
        self.batch_execute("BEGIN").await?;
        Ok(Transaction {
            inner: self.inner.clone(),
            done: false,
        })
    }

    pub async fn prepare(&self, query: &str) -> io::Result<Statement> {
        let pg_statement = self
            .pg_client()
            .await?
            .prepare(query)
            .await
            .map_err(pg_error)?;
        Ok(Statement {
            inner: pg_statement,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.inner.try_lock().map(|g| g.closed).unwrap_or(false)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Prepared PostgreSQL statement.
pub struct Statement {
    inner: tokio_postgres::Statement,
}
impl Statement {
    pub fn params(&self) -> &[tokio_postgres::types::Type] {
        self.inner.params()
    }
    pub fn columns(&self) -> &[tokio_postgres::Column] {
        self.inner.columns()
    }
}

/// Transaction handle. Dropping an unfinished handle closes the client so a
/// pooled connection cannot accidentally be reused with an open transaction.
pub struct Transaction {
    inner: Arc<Mutex<ClientInner>>,
    done: bool,
}
impl Transaction {
    async fn client(&self) -> io::Result<Arc<tokio_postgres::Client>> {
        let inner = self.inner.lock().await;
        inner
            .auth_state
            .check(target::SQL)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        if inner.closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "client is closed",
            ));
        }
        inner
            .client
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "client is not connected"))
    }
    pub async fn execute(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> io::Result<u64> {
        let client = self.client().await?;
        client.execute(query, params).await.map_err(pg_error)
    }
    pub async fn query(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> io::Result<Vec<Row>> {
        let client = self.client().await?;
        client.query(query, params).await.map_err(pg_error)
    }
    pub async fn commit(mut self) -> io::Result<()> {
        self.client()
            .await?
            .batch_execute("COMMIT")
            .await
            .map_err(pg_error)?;
        self.done = true;
        Ok(())
    }
    pub async fn rollback(mut self) -> io::Result<()> {
        self.client()
            .await?
            .batch_execute("ROLLBACK")
            .await
            .map_err(pg_error)?;
        self.done = true;
        Ok(())
    }
}
impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.done {
            if let Ok(mut inner) = self.inner.try_lock() {
                inner.closed = true;
                inner.client.take();
            }
        }
    }
}

/// Future that drives socket input and PostgreSQL responses.
pub struct Connection {
    task: Pin<Box<dyn Future<Output = io::Result<()>> + Send>>,
}
impl Future for Connection {
    type Output = io::Result<()>;
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.task.as_mut().poll(cx)
    }
}

fn pg_error(e: tokio_postgres::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnected_client_cannot_query_or_self_authenticate() {
        let client = Client::new();
        let err = client.query("SELECT 1", &[]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(client.authenticate("operator", "password").await.is_err());
        assert!(!client.is_authenticated().await);
    }

    #[test]
    fn config_has_postgres_defaults() {
        let config = Config::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.dbname, "test");
    }
}
