//! Secrets Test Ark - Test suite for OutLayer secrets via environment variables
//!
//! Uses the `outlayer` SDK for env access.
//!
//! Two kinds of secret reach a run, and this module reports both: the
//! AUTHOR's (`AUTHOR_SECRET`, named by the manifest carried in the published
//! artefact and decrypted into every run) and the CALLER's (`SECRET`,
//! `USER_SECRET`, ..., named by the call's `secrets_ref`). It also reports who
//! the run acts as and who paid, so one answer covers identity and access.

use outlayer::env;
use serde::{Deserialize, Serialize};

/// The published artefact's manifest: the author's secret profile. Only the
/// artefact built with `--features manifest` carries it — see Cargo.toml.
#[cfg(all(target_family = "wasm", feature = "manifest"))]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

#[derive(Deserialize)]
struct Input {
    /// Accepted so a caller's usual `{"message": ...}` input keeps parsing; the
    /// run reports secrets, not messages.
    #[allow(dead_code)]
    #[serde(default)]
    message: String,
    /// When set, the run performs one GET to this URL and reports the status.
    /// The manifest declares no network section, so an ordinary project with a
    /// manifest keeps unrestricted egress — this is how a test proves it.
    #[serde(default)]
    fetch_url: Option<String>,
}

#[derive(Serialize)]
struct SecretInfo {
    key: String,
    found: bool,
    value: Option<String>,
}

#[derive(Serialize)]
struct Output {
    success: bool,
    status: String,
    secrets: Vec<SecretInfo>,
    found_count: usize,
    total_count: usize,
    message: String,
    /// The author's secret reached this run (from the manifest, never the call).
    author: bool,
    /// The caller's `USER_SECRET` reached this run (from the call's `secrets_ref`).
    user: bool,
    /// Who the run acts as (`NEAR_SENDER_ID`) and who paid (`NEAR_USER_ACCOUNT_ID`).
    /// They differ only for a wallet running under a bound account's name.
    sender: Option<String>,
    payer: Option<String>,
    /// `fetch_url`, when asked: the HTTP status, or the refusal.
    fetch: Option<String>,
}

fn main() {
    let output = match env::input_json::<Input>() {
        Ok(Some(input)) => check_secrets(input.fetch_url.as_deref()),
        Ok(None) => check_secrets(None), // No input is fine, just check secrets
        Err(e) => Output {
            success: false,
            status: "error".to_string(),
            secrets: vec![],
            found_count: 0,
            total_count: 0,
            message: format!("Failed to parse input: {}", e),
            author: false,
            user: false,
            sender: None,
            payer: None,
            fetch: None,
        },
    };

    let _ = env::output_json(&output);
}

/// One GET, reported as a status line or as the refusal the host answered.
fn fetch(url: &str) -> String {
    match wasi_http_client::Client::new().get(url).send() {
        Ok(response) => format!("{}", response.status()),
        Err(e) => format!("refused: {e}"),
    }
}

fn check_secrets(fetch_url: Option<&str>) -> Output {
    let keys = [
        "SECRET",
        "ANOTHER_SECRET",
        "PROTECTED_SECRET",
        "PROTECTED_ANOTHER_SECRET",
        "AUTHOR_SECRET",
        "USER_SECRET",
    ];
    let mut secrets: Vec<SecretInfo> = Vec::new();

    // Try to read each key from environment
    for key in keys {
        let (found, value) = match std::env::var(key) {
            Ok(v) => (true, Some(v)),
            Err(_) => (false, None),
        };
        secrets.push(SecretInfo {
            key: key.to_string(),
            found,
            value,
        });
    }

    let found_count = secrets.iter().filter(|s| s.found).count();
    let total_count = secrets.len();

    let status = if found_count == total_count {
        "success"
    } else if found_count > 0 {
        "partial"
    } else {
        "not_found"
    };

    let message = format!(
        "Found {}/{} secrets: {}",
        found_count,
        total_count,
        secrets
            .iter()
            .map(|s| format!("{}={}", s.key, if s.found { "Y" } else { "N" }))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let present = |key: &str| secrets.iter().any(|s| s.key == key && s.found);
    let author = present("AUTHOR_SECRET");
    let user = present("USER_SECRET");

    Output {
        success: found_count > 0,
        status: status.to_string(),
        secrets,
        found_count,
        total_count,
        message,
        author,
        user,
        sender: std::env::var("NEAR_SENDER_ID").ok(),
        payer: std::env::var("NEAR_USER_ACCOUNT_ID").ok(),
        fetch: fetch_url.map(fetch),
    }
}
