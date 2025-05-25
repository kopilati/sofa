use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct MockAuditService {
    logs: Arc<Mutex<VecDeque<Value>>>,
    max_logs: usize,
}

impl MockAuditService {
    pub fn new(max_logs: usize) -> Self {
        Self {
            logs: Arc::new(Mutex::new(VecDeque::new())),
            max_logs,
        }
    }
    
    pub fn get_logs(&self) -> Vec<Value> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }
    
    pub fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
    }
    
    pub fn log_count(&self) -> usize {
        self.logs.lock().unwrap().len()
    }
    
    pub async fn start_server(self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/health", get(|| async { "OK" }))
            .route("/audit", post({
                let service = self.clone();
                move |Json(payload): Json<Value>| async move {
                    service.receive_log(payload).await
                }
            }));
        
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
    
    async fn receive_log(&self, log: Value) -> StatusCode {
        let mut logs = self.logs.lock().unwrap();
        
        if logs.len() >= self.max_logs {
            logs.pop_front();
        }
        
        logs.push_back(log);
        StatusCode::OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use serde_json::json;
    
    #[tokio::test]
    async fn test_mock_audit_service() {
        let service = MockAuditService::new(100);
        
        // Start server in background
        let server_service = service.clone();
        tokio::spawn(async move {
            server_service.start_server("127.0.0.1:0").await.unwrap();
        });
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Test receiving logs
        assert_eq!(service.log_count(), 0);
        
        // Simulate receiving a log
        let test_log = json!({
            "method": "GET",
            "path": "/test",
            "user_id": "test-user",
            "timestamp": 1640995200,
            "success": true,
            "status_code": 200
        });
        
        {
            let mut logs = service.logs.lock().unwrap();
            logs.push_back(test_log.clone());
        }
        
        assert_eq!(service.log_count(), 1);
        
        let retrieved_logs = service.get_logs();
        assert_eq!(retrieved_logs[0], test_log);
        
        service.clear_logs();
        assert_eq!(service.log_count(), 0);
    }
}