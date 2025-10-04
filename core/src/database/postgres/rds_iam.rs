use aws_rds_signer::Signer;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct RdsIamConfig {
    pub region: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub database: String,
    pub base_connection_string: String,
}

#[derive(Debug)]
pub struct RdsIamTokenManager {
    config: RdsIamConfig,
    current_token: RwLock<Option<String>>,
    token_expiry: RwLock<Option<SystemTime>>,
    signer: Signer,
}

impl RdsIamTokenManager {
    pub fn new(config: RdsIamConfig) -> Self {
        let signer = Signer::builder()
            .region(&config.region)
            .host(&config.hostname)
            .port(config.port)
            .user(&config.username)
            .build();

        Self { config, current_token: RwLock::new(None), token_expiry: RwLock::new(None), signer }
    }

    /// Check if we need to refresh the token (expires in < 5 minutes)
    async fn needs_refresh(&self) -> bool {
        let expiry = self.token_expiry.read().await;
        match *expiry {
            Some(expiry_time) => {
                let now = SystemTime::now();
                // Refresh if less than 5 minutes remaining
                let buffer = Duration::from_secs(5 * 60);
                now + buffer > expiry_time
            }
            None => true, // No token yet
        }
    }

    /// Get a fresh IAM authentication token
    pub async fn get_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if !self.needs_refresh().await {
            let token = self.current_token.read().await;
            if let Some(token) = token.as_ref() {
                return Ok(token.clone());
            }
        }

        // Need to refresh token
        info!("🔑 Refreshing RDS IAM authentication token for user: {}", self.config.username);

        let new_token = self
            .signer
            .fetch_token()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let expiry = SystemTime::now() + Duration::from_secs(15 * 60); // 15 minutes

        // Update stored token and expiry
        {
            let mut token = self.current_token.write().await;
            *token = Some(new_token.clone());
        }
        {
            let mut token_expiry = self.token_expiry.write().await;
            *token_expiry = Some(expiry);
        }

        info!("✅ Successfully refreshed RDS IAM token (expires in 15 minutes)");
        Ok(new_token)
    }

    /// Generate a connection string with current IAM token
    pub async fn get_connection_string(
        &self,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let token = self.get_token().await?;

        let connection_string = format!(
            "postgresql://{}:{}@{}:{}/{}?sslmode=require",
            self.config.username,
            urlencoding::encode(&token),
            self.config.hostname,
            self.config.port,
            self.config.database
        );

        Ok(connection_string)
    }
}

/// Parse a connection string to detect RDS IAM authentication
pub fn parse_rds_iam_config(
    connection_string: &str,
) -> Result<Option<RdsIamConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let parsed_url = Url::parse(connection_string)?;

    let host = match parsed_url.host_str() {
        Some(host) => host,
        None => return Ok(None), // Not a valid URL
    };

    // Check if this is an RDS endpoint
    if !host.contains("rds.amazonaws.com") && !host.contains("amazonaws.com") {
        return Ok(None); // Not an RDS endpoint
    }

    // Extract region from RDS endpoint (e.g., mydb.abc123.us-east-1.rds.amazonaws.com)
    let region = extract_aws_region_from_endpoint(host)?;

    let port = parsed_url.port().unwrap_or(5432);
    let username = parsed_url.username().to_string();
    let database = parsed_url.path().trim_start_matches('/').to_string();

    if database.is_empty() {
        warn!("No database name found in RDS IAM connection string");
        return Ok(None);
    }

    // Check if password is provided - if so, it's regular auth, not IAM
    if parsed_url.password().is_some() {
        return Ok(None); // Has password, so not IAM auth
    }

    info!("🔍 Detected RDS IAM configuration: user={}, host={}, region={}", username, host, region);

    Ok(Some(RdsIamConfig {
        region,
        hostname: host.to_string(),
        port,
        username,
        database,
        base_connection_string: connection_string.to_string(),
    }))
}

/// Extract AWS region from RDS endpoint hostname
fn extract_aws_region_from_endpoint(
    endpoint: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let parts: Vec<&str> = endpoint.split('.').collect();

    // Check for Global Database endpoint: identifier.global-xyz.global.rds.amazonaws.com
    if parts.contains(&"global") && parts.contains(&"rds") && parts.contains(&"amazonaws") {
        info!("🌍 Detected AWS RDS Global Database endpoint: {}", endpoint);

        // For Global Database, we need to determine the current region
        // Try multiple methods in order of preference:

        // 1. Check AWS_REGION environment variable
        if let Ok(region) = std::env::var("AWS_REGION") {
            if !region.is_empty() {
                info!("Using region from AWS_REGION: {}", region);
                return Ok(region);
            }
        }

        // 2. Check AWS_DEFAULT_REGION environment variable
        if let Ok(region) = std::env::var("AWS_DEFAULT_REGION") {
            if !region.is_empty() {
                info!("Using region from AWS_DEFAULT_REGION: {}", region);
                return Ok(region);
            }
        }

        // 3. Default to us-east-1 (most common region for global services)
        warn!(
            "⚠️  Global RDS endpoint detected but no AWS region found in environment. Defaulting to us-east-1"
        );
        warn!(
            "💡 Set AWS_REGION or AWS_DEFAULT_REGION environment variable for accurate region detection"
        );
        return Ok("us-east-1".to_string());
    }

    // Handle regular regional endpoint: identifier.random.region.rds.amazonaws.com
    for (i, part) in parts.iter().enumerate() {
        if *part == "rds" && i > 0 {
            let region = parts[i - 1];

            // Validate it looks like an AWS region (e.g., us-east-1, eu-west-1)
            if region.len() >= 6 && region.contains('-') {
                info!("📍 Detected regional RDS endpoint with region: {}", region);
                return Ok(region.to_string());
            }
        }
    }

    Err("Could not extract AWS region from RDS endpoint. Supported formats: regional (db.xyz.us-east-1.rds.amazonaws.com) or global (db.global-xyz.global.rds.amazonaws.com)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rds_iam_config() {
        // RDS IAM connection (no password)
        let rds_iam = "postgresql://myuser@mydb.abc123.us-east-1.rds.amazonaws.com:5432/mydb";
        let config = parse_rds_iam_config(rds_iam).unwrap();
        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.username, "myuser");
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.database, "mydb");

        // Regular connection (has password)
        let regular = "postgresql://user:pass@mydb.abc123.us-east-1.rds.amazonaws.com:5432/mydb";
        let config = parse_rds_iam_config(regular).unwrap();
        assert!(config.is_none()); // Should not be detected as IAM

        // Non-RDS connection
        let local = "postgresql://user@localhost:5432/mydb";
        let config = parse_rds_iam_config(local).unwrap();
        assert!(config.is_none()); // Should not be detected as IAM
    }

    #[test]
    fn test_extract_aws_region_from_endpoint() {
        // Test regional endpoints
        let endpoint1 = "mydb.abc123.us-east-1.rds.amazonaws.com";
        assert_eq!(extract_aws_region_from_endpoint(endpoint1).unwrap(), "us-east-1");

        let endpoint2 = "cluster.xyz789.eu-west-1.rds.amazonaws.com";
        assert_eq!(extract_aws_region_from_endpoint(endpoint2).unwrap(), "eu-west-1");

        let endpoint3 = "instance.cluster-abc.ap-southeast-2.rds.amazonaws.com";
        assert_eq!(extract_aws_region_from_endpoint(endpoint3).unwrap(), "ap-southeast-2");

        // Test global endpoints (should use environment or default)
        unsafe {
            std::env::set_var("AWS_REGION", "us-west-2");
        }
        let global_endpoint =
            "global-staging-aave-rds-aurora.global-gb0wxooppbgw.global.rds.amazonaws.com";
        assert_eq!(extract_aws_region_from_endpoint(global_endpoint).unwrap(), "us-west-2");

        // Test global endpoint without AWS_REGION (should default to us-east-1)
        unsafe {
            std::env::remove_var("AWS_REGION");
            std::env::remove_var("AWS_DEFAULT_REGION");
        }
        assert_eq!(extract_aws_region_from_endpoint(global_endpoint).unwrap(), "us-east-1");
    }
}
