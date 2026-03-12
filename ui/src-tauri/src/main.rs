#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use socketguard_core::api_types::*;
use socketguard_core::Policy;

const DEFAULT_API: &str = "http://127.0.0.1:9476";

fn api_base() -> String {
    std::env::var("SOCKETGUARD_API").unwrap_or_else(|_| DEFAULT_API.to_string())
}

#[tauri::command]
async fn list_sockets() -> Result<SocketListResponse, String> {
    let client = reqwest::Client::new();
    client
        .get(format!("{}/api/sockets", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_socket(id: String) -> Result<SocketDetailResponse, String> {
    let client = reqwest::Client::new();
    client
        .get(format!("{}/api/sockets/{id}", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn allow_ip(socket_id: String, ip: String, label: Option<String>) -> Result<(), String> {
    let client = reqwest::Client::new();
    let req = AllowIpRequest {
        allowed_ip: ip,
        label,
    };
    let resp = client
        .post(format!("{}/api/sockets/{socket_id}/acl/allow", api_base()))
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn remove_acl_entry(socket_id: String, entry_id: i64) -> Result<(), String> {
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!(
            "{}/api/sockets/{socket_id}/acl/{entry_id}",
            api_base()
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn set_policy(socket_id: String, policy: String) -> Result<(), String> {
    let client = reqwest::Client::new();
    let policy: Policy = policy.parse().map_err(|e: String| e)?;
    let req = UpdatePolicyRequest { policy };
    let resp = client
        .put(format!("{}/api/sockets/{socket_id}/policy", api_base()))
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

#[tauri::command]
async fn get_config() -> Result<ConfigResponse, String> {
    let client = reqwest::Client::new();
    client
        .get(format!("{}/api/config", api_base()))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_config(config: UpdateConfigRequest) -> Result<(), String> {
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}/api/config", api_base()))
        .json(&config)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let err: ApiError = resp.json().await.map_err(|e| e.to_string())?;
        Err(err.error)
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            list_sockets,
            get_socket,
            allow_ip,
            remove_acl_entry,
            set_policy,
            get_config,
            update_config,
        ])
        .run(tauri::generate_context!())
        .expect("error running SocketGuard UI");
}
