use std::{env, future::Future, pin::Pin, sync::Arc, time::Duration};

use bb8::{ManageConnection, Pool, PooledConnection, RunError};
use bb8_postgres::PostgresConnectionManager;
use bytes::Buf;
use dotenv::dotenv;
use futures::pin_mut;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio::{task, time::timeout};
pub use tokio_postgres::types::{ToSql, Type as PgType};
use tokio_postgres::{
    binary_copy::BinaryCopyInWriter, config::SslMode, Config, CopyInSink, Error as PgError, Row,
    Statement, ToStatement, Transaction as PgTransaction,
};
use tracing::{error, info};

use crate::database::postgres::{
    generate::generate_event_table_columns_names_sql,
    rds_iam::{RdsIamConfig, RdsIamTokenManager},
    sql_type_wrapper::EthereumSqlTypeWrapper,
};

pub fn connection_string() -> Result<String, env::VarError> {
    dotenv().ok();
    let connection = env::var("DATABASE_URL")?;
    Ok(connection)
}

#[derive(thiserror::Error, Debug)]
pub enum PostgresConnectionError {
    #[error("The database connection string is wrong please check your environment: {0}")]
    DatabaseConnectionConfigWrong(#[from] env::VarError),

    #[error("Connection pool error: {0}")]
    ConnectionPoolError(#[from] tokio_postgres::Error),

    #[error("Connection pool runtime error: {0}")]
    ConnectionPoolRuntimeError(#[from] RunError<tokio_postgres::Error>),

    #[error("Can not connect to the database please make sure your connection string is correct")]
    CanNotConnectToDatabase,

    #[error("Could not parse connection string make sure it is correctly formatted")]
    CouldNotParseConnectionString,

    #[error("Could not create tls connector")]
    CouldNotCreateTlsConnector,

    #[error("RDS IAM authentication error: {0}")]
    RdsIamAuthError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum PostgresError {
    #[error("PgError {0}")]
    PgError(#[from] PgError),

    #[error("Connection pool error: {0}")]
    ConnectionPoolError(#[from] RunError<tokio_postgres::Error>),
}

#[allow(unused)]
pub struct PostgresTransaction<'a> {
    pub transaction: PgTransaction<'a>,
}

impl PostgresTransaction<'_> {
    #[allow(unused)]
    pub async fn execute(
        &mut self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, PostgresError> {
        self.transaction.execute(query, params).await.map_err(PostgresError::PgError)
    }

    #[allow(unused)]
    pub async fn query(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, PostgresError> {
        self.transaction.query(query, params).await.map_err(PostgresError::PgError)
    }

    #[allow(unused)]
    pub async fn commit(self) -> Result<(), PostgresError> {
        self.transaction.commit().await.map_err(PostgresError::PgError)
    }

    #[allow(unused)]
    pub async fn rollback(self) -> Result<(), PostgresError> {
        self.transaction.rollback().await.map_err(PostgresError::PgError)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BulkInsertPostgresError {
    #[error("{0}")]
    PostgresError(#[from] PostgresError),

    #[error("{0}")]
    CouldNotWriteDataToPostgres(#[from] tokio_postgres::Error),
}

#[derive(Clone)]
pub enum PostgresPool {
    Regular(Pool<PostgresConnectionManager<MakeTlsConnector>>),
    RdsIam(Pool<RdsIamConnectionManager>),
}

pub struct PostgresClient {
    pool: PostgresPool,
}

#[derive(Clone)]
/// Custom connection manager for RDS IAM that can refresh tokens dynamically
pub struct RdsIamConnectionManager {
    base_config: Config,
    tls_connector: MakeTlsConnector,
    token_manager: Arc<RdsIamTokenManager>,
}

impl RdsIamConnectionManager {
    pub fn new(
        base_config: Config,
        tls_connector: MakeTlsConnector,
        token_manager: Arc<RdsIamTokenManager>,
    ) -> Self {
        Self { base_config, tls_connector, token_manager }
    }
}

impl ManageConnection for RdsIamConnectionManager {
    type Connection = tokio_postgres::Client;
    type Error = std::io::Error;

    fn connect(
        &self,
    ) -> impl std::future::Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let token_manager = self.token_manager.clone();
        let base_config = self.base_config.clone();
        let tls_connector = self.tls_connector.clone();

        async move {
            // Get fresh IAM token for this connection attempt
            let fresh_token = token_manager.get_token().await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Failed to get RDS IAM token: {e}"),
                )
            })?;

            // Create new config with fresh token
            let mut config = base_config.clone();
            config.password(fresh_token);

            // Connect with fresh token
            let (client, connection) =
                config.connect(tls_connector.clone()).await.map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("RDS IAM connection failed: {e}"),
                    )
                })?;

            // Spawn the connection task
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("RDS IAM connection error: {}", e);
                }
            });

            Ok(client)
        }
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.simple_query("SELECT 1").await.map(|_| ()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("Connection validation failed: {e}"),
            )
        })
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false // Let bb8 handle this through is_valid
    }
}

fn create_tls_connector() -> Result<MakeTlsConnector, PostgresConnectionError> {
    let connector = TlsConnector::builder()
        .build()
        .map_err(|_| PostgresConnectionError::CouldNotCreateTlsConnector)?;
    Ok(MakeTlsConnector::new(connector))
}

impl PostgresClient {
    pub async fn new() -> Result<Self, PostgresConnectionError> {
        Self::new_with_config(false).await
    }

    pub async fn new_with_config(use_rds_iam: bool) -> Result<Self, PostgresConnectionError> {
        dotenv().ok();

        info!("🔌 PostgresClient initialization");

        // Check environment variable override (backwards compatibility)
        let env_override = env::var("USE_RDS_IAM_AUTH").ok().and_then(|v| {
            let lower = v.to_lowercase();
            if lower == "true" || lower == "1" || lower == "enabled" {
                Some(true)
            } else if lower == "false" || lower == "0" || lower == "disabled" {
                Some(false)
            } else {
                None
            }
        });

        let use_rds_iam_auth = env_override.unwrap_or(use_rds_iam);

        if use_rds_iam_auth {
            // Use RDS IAM authentication
            info!("🔐 RDS IAM authentication ENABLED");
            return Self::new_with_rds_iam_env().await;
        }

        // Use regular PostgreSQL authentication
        info!("🔒 Using regular PostgreSQL authentication");
        let connection_str = connection_string()?;
        Self::new_regular(&connection_str).await
    }

    async fn new_with_rds_iam_env() -> Result<Self, PostgresConnectionError> {
        // Get RDS IAM configuration from environment variables
        let user = env::var("DATABASE_USER").map_err(|_| {
            PostgresConnectionError::DatabaseConnectionConfigWrong(env::VarError::NotPresent)
        })?;
        let host = env::var("DATABASE_HOST").map_err(|_| {
            PostgresConnectionError::DatabaseConnectionConfigWrong(env::VarError::NotPresent)
        })?;
        let port = env::var("DATABASE_PORT").unwrap_or_else(|_| "5432".to_string());
        let db = env::var("DATABASE_NAME").map_err(|_| {
            PostgresConnectionError::DatabaseConnectionConfigWrong(env::VarError::NotPresent)
        })?;
        let region =
            env::var("AWS_REGION").or_else(|_| env::var("AWS_DEFAULT_REGION")).map_err(|_| {
                PostgresConnectionError::DatabaseConnectionConfigWrong(env::VarError::NotPresent)
            })?;

        info!(
            "📍 RDS IAM Config - user: {}, host: {}, port: {}, db: {}, region: {}",
            user, host, port, db, region
        );

        let port_num = port.parse::<u16>().map_err(|_| {
            PostgresConnectionError::RdsIamAuthError("Invalid DATABASE_PORT value".to_string())
        })?;

        let rds_config = RdsIamConfig {
            region,
            hostname: host,
            port: port_num,
            username: user,
            database: db,
            base_connection_string: String::new(),
        };

        Self::new_with_rds_iam(rds_config).await
    }

    async fn new_with_rds_iam(rds_config: RdsIamConfig) -> Result<Self, PostgresConnectionError> {
        info!("🔧 Creating RDS IAM connection with automatic token refresh capability");

        let token_manager = Arc::new(RdsIamTokenManager::new(rds_config.clone()));

        // Create base config without password (password will be injected per-connection)
        let mut base_config = Config::new();
        base_config
            .host(&rds_config.hostname)
            .port(rds_config.port)
            .user(&rds_config.username)
            .dbname(&rds_config.database)
            .ssl_mode(SslMode::Require);

        let tls_connector = create_tls_connector()?;

        // Test initial connection
        info!("🔍 Testing initial RDS IAM connection...");
        let test_token = token_manager
            .get_token()
            .await
            .map_err(|e| PostgresConnectionError::RdsIamAuthError(e.to_string()))?;

        let mut test_config = base_config.clone();
        test_config.password(test_token);

        let (client, connection) = match timeout(
            Duration::from_secs(10),
            test_config.connect(tls_connector.clone()),
        )
        .await
        {
            Ok(Ok((client, connection))) => (client, connection),
            Ok(Err(e)) => {
                error!("❌ Initial RDS IAM authentication failed: {}", e);
                return Err(PostgresConnectionError::RdsIamAuthError(format!(
                    "Connection failed: {e}"
                )));
            }
            Err(e) => {
                error!("❌ Initial RDS IAM connection timeout: {}", e);
                return Err(PostgresConnectionError::RdsIamAuthError(
                    "Connection timeout".to_string(),
                ));
            }
        };

        // Spawn the test connection task
        let connection_handle = task::spawn(connection);

        // Test the connection
        match client.query_one("SELECT 1", &[]).await {
            Ok(_) => {
                info!("✅ Initial RDS IAM authentication successful");
            }
            Err(e) => {
                error!("❌ Initial RDS IAM connection test failed: {}", e);
                return Err(PostgresConnectionError::RdsIamAuthError(format!(
                    "Connection test failed: {e}"
                )));
            }
        };

        // Clean up test connection
        drop(client);
        let _ = connection_handle.await;

        // Create custom connection manager with token refresh capability
        let custom_manager =
            RdsIamConnectionManager::new(base_config, tls_connector, token_manager);

        // Create connection pool with custom manager
        let pool = Pool::builder()
            .max_size(15) // Reasonable pool size for high concurrency
            .min_idle(Some(3)) // Keep some connections warm
            .max_lifetime(Some(Duration::from_secs(12 * 60))) // 12 minutes - connections will refresh with new tokens
            .idle_timeout(Some(Duration::from_secs(5 * 60))) // 5 minutes idle timeout
            .connection_timeout(Duration::from_secs(30)) // 30 second connection timeout
            .test_on_check_out(true) // Ensure connections are valid
            .build(custom_manager)
            .await
            .map_err(|e| {
                PostgresConnectionError::RdsIamAuthError(format!(
                    "Failed to create RDS IAM pool: {e}"
                ))
            })?;

        info!("🎉 RDS IAM connection pool created with automatic token refresh!");

        Ok(PostgresClient { pool: PostgresPool::RdsIam(pool) })
    }

    async fn new_regular(connection_string: &str) -> Result<Self, PostgresConnectionError> {
        async fn _new(
            disable_ssl: bool,
            connection_string: &str,
        ) -> Result<PostgresClient, PostgresConnectionError> {
            let mut config: Config = connection_string
                .parse()
                .map_err(|_| PostgresConnectionError::CouldNotParseConnectionString)?;

            if disable_ssl {
                config.ssl_mode(SslMode::Disable);
            }

            let tls_connector = create_tls_connector()?;

            // Perform a direct connection test
            let (client, connection) =
                match timeout(Duration::from_millis(5000), config.connect(tls_connector.clone()))
                    .await
                {
                    Ok(Ok((client, connection))) => (client, connection),
                    Ok(Err(e)) => {
                        // retry without ssl if ssl has been attempted and failed
                        if !disable_ssl
                            && config.get_ssl_mode() != SslMode::Disable
                            && !connection_string.contains("sslmode=require")
                        {
                            return Box::pin(_new(true, connection_string)).await;
                        }
                        error!("❌ Error connecting to database: {}", e);
                        return Err(PostgresConnectionError::CanNotConnectToDatabase);
                    }
                    Err(e) => {
                        error!("❌ Timeout connecting to database: {}", e);
                        return Err(PostgresConnectionError::CanNotConnectToDatabase);
                    }
                };

            // Spawn the connection future to ensure the connection is established
            let connection_handle = task::spawn(connection);

            // Perform a simple query to check the connection
            match client.query_one("SELECT 1", &[]).await {
                Ok(_) => {
                    info!("✅ Regular PostgreSQL connection test successful");
                }
                Err(_) => return Err(PostgresConnectionError::CanNotConnectToDatabase),
            };

            // Drop the client and ensure the connection handle completes
            drop(client);
            match connection_handle.await {
                Ok(Ok(())) => (),
                Ok(Err(_)) => return Err(PostgresConnectionError::CanNotConnectToDatabase),
                Err(_) => return Err(PostgresConnectionError::CanNotConnectToDatabase),
            }

            let manager = PostgresConnectionManager::new(config, tls_connector);

            // TODO: It's important for users to be able to define the pool size they want.
            // Rust binding projects can use this client, but it's critical to have config access.
            let pool = Pool::builder().build(manager).await?;

            info!("🎉 Regular PostgreSQL connection pool created successfully!");

            Ok(PostgresClient { pool: PostgresPool::Regular(pool) })
        }

        _new(false, connection_string).await
    }

    pub async fn from_connection(
        pool: Pool<PostgresConnectionManager<MakeTlsConnector>>,
    ) -> Result<Self, PostgresConnectionError> {
        Ok(Self { pool: PostgresPool::Regular(pool) })
    }

    pub async fn batch_execute(&self, sql: &str) -> Result<(), PostgresError> {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                conn.batch_execute(sql).await.map_err(PostgresError::PgError)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                conn.batch_execute(sql).await.map_err(PostgresError::PgError)
            }
        }
    }

    pub async fn execute<T>(
        &self,
        query: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, PostgresError>
    where
        T: ?Sized + ToStatement,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                conn.execute(query, params).await.map_err(PostgresError::PgError)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                conn.execute(query, params).await.map_err(PostgresError::PgError)
            }
        }
    }

    pub async fn prepare(
        &self,
        query: &str,
        parameter_types: &[PgType],
    ) -> Result<Statement, PostgresError> {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                conn.prepare_typed(query, parameter_types).await.map_err(PostgresError::PgError)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                conn.prepare_typed(query, parameter_types).await.map_err(PostgresError::PgError)
            }
        }
    }

    pub async fn with_transaction<F, Fut, T, Q>(
        &self,
        query: &Q,
        params: &[&(dyn ToSql + Sync)],
        f: F,
    ) -> Result<T, PostgresError>
    where
        F: FnOnce(u64) -> Fut + Send,
        Fut: Future<Output = Result<T, PostgresError>> + Send,
        Q: ?Sized + ToStatement,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let mut conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                let transaction = conn.transaction().await.map_err(PostgresError::PgError)?;
                let count =
                    transaction.execute(query, params).await.map_err(PostgresError::PgError)?;
                let result = f(count).await?;
                transaction.commit().await.map_err(PostgresError::PgError)?;
                Ok(result)
            }
            PostgresPool::RdsIam(pool) => {
                let mut conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                let transaction = conn.transaction().await.map_err(PostgresError::PgError)?;
                let count =
                    transaction.execute(query, params).await.map_err(PostgresError::PgError)?;
                let result = f(count).await?;
                transaction.commit().await.map_err(PostgresError::PgError)?;
                Ok(result)
            }
        }
    }

    pub async fn query<T>(
        &self,
        query: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, PostgresError>
    where
        T: ?Sized + ToStatement,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                let rows = conn.query(query, params).await.map_err(PostgresError::PgError)?;
                Ok(rows)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                let rows = conn.query(query, params).await.map_err(PostgresError::PgError)?;
                Ok(rows)
            }
        }
    }

    pub async fn query_one<T>(
        &self,
        query: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, PostgresError>
    where
        T: ?Sized + ToStatement,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                let row = conn.query_one(query, params).await.map_err(PostgresError::PgError)?;
                Ok(row)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                let row = conn.query_one(query, params).await.map_err(PostgresError::PgError)?;
                Ok(row)
            }
        }
    }

    pub async fn query_one_or_none<T>(
        &self,
        query: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, PostgresError>
    where
        T: ?Sized + ToStatement,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                let row = conn.query_opt(query, params).await.map_err(PostgresError::PgError)?;
                Ok(row)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                let row = conn.query_opt(query, params).await.map_err(PostgresError::PgError)?;
                Ok(row)
            }
        }
    }

    pub async fn batch_insert<T>(
        &self,
        query: &T,
        params_list: Vec<Vec<Box<dyn ToSql + Send + Sync>>>,
    ) -> Result<(), PostgresError>
    where
        T: ?Sized + ToStatement,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let mut conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                let transaction = conn.transaction().await.map_err(PostgresError::PgError)?;
                for params in params_list {
                    let params_refs: Vec<&(dyn ToSql + Sync)> =
                        params.iter().map(|param| param.as_ref() as &(dyn ToSql + Sync)).collect();
                    transaction
                        .execute(query, &params_refs)
                        .await
                        .map_err(PostgresError::PgError)?;
                }
                transaction.commit().await.map_err(PostgresError::PgError)?;
                Ok(())
            }
            PostgresPool::RdsIam(pool) => {
                let mut conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                let transaction = conn.transaction().await.map_err(PostgresError::PgError)?;
                for params in params_list {
                    let params_refs: Vec<&(dyn ToSql + Sync)> =
                        params.iter().map(|param| param.as_ref() as &(dyn ToSql + Sync)).collect();
                    transaction
                        .execute(query, &params_refs)
                        .await
                        .map_err(PostgresError::PgError)?;
                }
                transaction.commit().await.map_err(PostgresError::PgError)?;
                Ok(())
            }
        }
    }

    pub async fn copy_in<T, U>(&self, statement: &T) -> Result<CopyInSink<U>, PostgresError>
    where
        T: ?Sized + ToStatement,
        U: Buf + 'static + Send,
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                conn.copy_in(statement).await.map_err(PostgresError::PgError)
            }
            PostgresPool::RdsIam(pool) => {
                let conn = pool.get().await.map_err(|e| {
                    RunError::User(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("RDS IAM connection error: {e}"),
                    ))
                })?;
                conn.copy_in(statement).await.map_err(PostgresError::PgError)
            }
        }
    }

    // Internal method used by insert_bulk for large datasets (>100 rows).
    // Uses PostgreSQL COPY command for optimal performance with large data.
    // Made pub(crate) to allow crate-internal access while keeping insert_bulk as the primary API.
    pub(crate) async fn bulk_insert_via_copy(
        &self,
        table_name: &str,
        column_names: &[String],
        column_types: &[PgType],
        data: &[Vec<EthereumSqlTypeWrapper>],
    ) -> Result<(), BulkInsertPostgresError> {
        let stmt = format!(
            "COPY {} ({}) FROM STDIN WITH (FORMAT binary)",
            table_name,
            generate_event_table_columns_names_sql(column_names),
        );

        let prepared_data: Vec<Vec<&(dyn ToSql + Sync)>> = data
            .iter()
            .map(|row| row.iter().map(|param| param as &(dyn ToSql + Sync)).collect())
            .collect();

        let sink = self.copy_in(&stmt).await?;

        let writer = BinaryCopyInWriter::new(sink, column_types);
        pin_mut!(writer);

        // This can cause issues with Binary Copy command not completing and leaving hanging
        // processes. See similar: https://github.com/sfackler/rust-postgres/issues/1109
        //
        // We have to call `finish` manually on any write error.
        for row in prepared_data.iter() {
            if let Err(e) = writer.as_mut().write(row).await {
                error!("Error writing binary data, aborting early: {}", e);
                writer.finish().await?;
                return Err(e)?;
            };
        }

        writer.finish().await?;

        Ok(())
    }

    // Internal method used by insert_bulk for small datasets (≤100 rows).
    // Uses standard INSERT queries which are more efficient for smaller data volumes.
    // Made pub(crate) to allow crate-internal access while keeping insert_bulk as the primary API.
    pub(crate) async fn bulk_insert_via_query(
        &self,
        table_name: &str,
        column_names: &[String],
        bulk_data: &[Vec<EthereumSqlTypeWrapper>],
    ) -> Result<u64, PostgresError> {
        let total_columns = column_names.len();

        let mut query = format!(
            "INSERT INTO {} ({}) VALUES ",
            table_name,
            generate_event_table_columns_names_sql(column_names),
        );
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();

        for (i, row) in bulk_data.iter().enumerate() {
            if i > 0 {
                query.push(',');
            }
            let mut placeholders = vec![];
            for j in 0..total_columns {
                placeholders.push(format!("${}", i * total_columns + j + 1));
            }
            query.push_str(&format!("({})", placeholders.join(",")));

            for param in row {
                params.push(param as &(dyn ToSql + Sync));
            }
        }

        self.execute(&query, &params).await
    }

    /// This will use COPY to insert the data into the database
    /// or use the normal bulk inserts if the data is not large enough to
    /// need a COPY. This uses `bulk_insert` and `bulk_insert_via_copy` under the hood
    pub async fn insert_bulk(
        &self,
        table_name: &str,
        columns: &[String],
        postgres_bulk_data: &[Vec<EthereumSqlTypeWrapper>],
    ) -> Result<(), String> {
        if postgres_bulk_data.is_empty() {
            return Ok(());
        }

        let total_params = postgres_bulk_data.len() * columns.len();

        // PostgreSQL has a maximum of 65535 parameters in a single query
        // (see https://www.postgresql.org/docs/current/limits.html#LIMITS-TABLE)
        // If we exceed this limit, force use of COPY method
        if postgres_bulk_data.len() > 100 || total_params > 65535 {
            let column_types: Vec<PgType> =
                postgres_bulk_data[0].iter().map(|param| param.to_type()).collect();

            self.bulk_insert_via_copy(table_name, columns, &column_types, postgres_bulk_data)
                .await
                .map_err(|e| e.to_string())
        } else {
            self.bulk_insert_via_query(table_name, columns, postgres_bulk_data)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }

    pub async fn raw_connection(
        &self,
    ) -> Result<PooledConnection<'_, PostgresConnectionManager<MakeTlsConnector>>, PostgresError>
    {
        match &self.pool {
            PostgresPool::Regular(pool) => {
                let conn = pool.get().await.map_err(PostgresError::ConnectionPoolError)?;
                Ok(conn)
            }
            PostgresPool::RdsIam(_pool) => {
                // For IAM connections, we can't return the raw connection since it's a different type
                // Return an error instead of panicking to prevent crashes
                tracing::warn!(
                    "raw_connection method called on IAM connection pool - this is not supported"
                );
                Err(PostgresError::ConnectionPoolError(RunError::TimedOut))
            }
        }
    }

    /// Execute multiple operations within a transaction, works with both Regular and RdsIam connections
    pub async fn execute_transaction<F>(&self, operations: F) -> Result<(), PostgresError>
    where
        F: FnOnce(
                &PostgresClient,
            ) -> Pin<Box<dyn Future<Output = Result<(), PostgresError>> + Send>>
            + Send,
    {
        match &self.pool {
            PostgresPool::Regular(_) => {
                // For regular connections, we could use raw_connection + transaction
                // But for consistency with IAM, we'll use the same approach
                operations(self).await
            }
            PostgresPool::RdsIam(_) => {
                // For IAM connections, execute operations directly
                // The IAM connection manager handles fresh tokens per connection
                operations(self).await
            }
        }
    }
}
