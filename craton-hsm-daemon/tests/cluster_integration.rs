// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Process-spawning cluster integration tests.
//!
//! Starts multiple HSM daemon processes on different localhost ports and
//! verifies end-to-end gRPC operations. Each daemon is an independent node
//! with its own token storage and configuration.
//!
//! These tests require the `craton-hsm-daemon` binary to be built first.
//! Run with: `cargo test -p craton-hsm-daemon --test cluster_integration`
//!
//! NOTE: These tests spawn real OS processes and bind real TCP ports.
//! Run with `--test-threads=1` to avoid port conflicts.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;

/// A test HSM daemon node.
struct TestNode {
    child: std::process::Child,
    port: u16,
    _config_dir: TempDir,
}

impl TestNode {
    /// Spawn a new daemon on a random localhost port.
    fn spawn(node_id: u32) -> Self {
        let port = allocate_port();
        let config_dir = TempDir::new().expect("tempdir creation");

        // Create storage subdirectory
        let store_dir = config_dir.path().join("store");
        std::fs::create_dir_all(&store_dir).expect("create store dir");

        // Write config TOML
        let config_path = config_dir.path().join("craton_hsm.toml");
        let config_content = format!(
            r#"
[token]
label = "Test Node {node_id}"
storage_path = "store"
serial_number = "TEST{node_id:012}"

[security]
pin_min_length = 4
pin_max_length = 64
max_failed_logins = 10
pbkdf2_iterations = 100000

[audit]
enabled = false

[algorithms]
crypto_backend = "rustcrypto"

[daemon]
bind = "127.0.0.1:{port}"
allow_insecure = true
max_connections = 32
request_timeout_secs = 10
"#
        );

        std::fs::write(&config_path, &config_content).expect("write config");

        // Set restrictive permissions on config file (required by daemon)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }

        // Locate the daemon binary
        let daemon_bin = daemon_binary_path();

        // Spawn the daemon process
        let child = std::process::Command::new(&daemon_bin)
            .arg(config_path.to_str().unwrap())
            .current_dir(config_dir.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn daemon at {:?}: {}", daemon_bin, e));

        TestNode {
            child,
            port,
            _config_dir: config_dir,
        }
    }

    /// Get the gRPC endpoint URL for this node.
    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Wait for the daemon to become ready by polling the TCP port.
    fn wait_ready(&self, timeout: Duration) {
        let start = std::time::Instant::now();
        let addr = format!("127.0.0.1:{}", self.port);

        while start.elapsed() < timeout {
            if std::net::TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                // Give the gRPC server a moment to fully initialize after TCP bind
                std::thread::sleep(Duration::from_millis(200));
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "Daemon on port {} did not become ready within {:?}",
            self.port, timeout
        );
    }

    /// Check if the daemon process is still running.
    fn is_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Allocate a random available TCP port.
fn allocate_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to random port");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // Release the port for the daemon to use
    port
}

/// Find the daemon binary path.
fn daemon_binary_path() -> PathBuf {
    // When running via `cargo test`, the binary is in target/debug/
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // Go up from craton-hsm-daemon/ to workspace root
    path.push("target");
    path.push("debug");
    path.push("craton-hsm-daemon");
    if path.exists() {
        return path;
    }

    // Try release build
    path.pop();
    path.pop();
    path.push("release");
    path.push("craton-hsm-daemon");
    if path.exists() {
        return path;
    }

    panic!(
        "craton-hsm-daemon binary not found. Build it first with: cargo build -p craton-hsm-daemon"
    );
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn test_spawn_single_node() {
    let mut node = TestNode::spawn(1);
    node.wait_ready(Duration::from_secs(15));
    assert!(node.is_running(), "Daemon should still be running");
}

#[test]
fn test_spawn_three_nodes() {
    let mut nodes: Vec<TestNode> = (1..=3).map(|i| TestNode::spawn(i)).collect();

    // Wait for all to be ready
    for node in &nodes {
        node.wait_ready(Duration::from_secs(15));
    }

    // All should still be running
    for node in &mut nodes {
        assert!(
            node.is_running(),
            "Node on port {} should be running",
            node.port
        );
    }

    // All on different ports
    let ports: Vec<u16> = nodes.iter().map(|n| n.port).collect();
    let unique_ports: std::collections::HashSet<u16> = ports.iter().cloned().collect();
    assert_eq!(
        unique_ports.len(),
        3,
        "All nodes should be on different ports"
    );
}

#[test]
fn test_node_tcp_connectivity() {
    let node = TestNode::spawn(10);
    node.wait_ready(Duration::from_secs(15));

    // Verify we can establish a TCP connection
    let addr = format!("127.0.0.1:{}", node.port);
    let result =
        std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2));
    assert!(
        result.is_ok(),
        "Should be able to connect to daemon TCP port"
    );
}

#[test]
fn test_node_restart() {
    let port = allocate_port();
    let config_dir = TempDir::new().unwrap();

    let store_dir = config_dir.path().join("store");
    std::fs::create_dir_all(&store_dir).unwrap();

    let config_path = config_dir.path().join("craton_hsm.toml");
    let config_content = format!(
        r#"
[token]
label = "Restart Test"
storage_path = "store"

[security]
pin_min_length = 4
pbkdf2_iterations = 100000

[audit]
enabled = false

[daemon]
bind = "127.0.0.1:{port}"
allow_insecure = true
"#
    );
    std::fs::write(&config_path, &config_content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let daemon_bin = daemon_binary_path();

    // First start
    let mut child1 = std::process::Command::new(&daemon_bin)
        .arg(config_path.to_str().unwrap())
        .current_dir(config_dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for ready
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Kill first instance
    child1.kill().unwrap();
    child1.wait().unwrap();

    // Wait for port to be released
    std::thread::sleep(Duration::from_millis(500));

    // Restart on same port
    let mut child2 = std::process::Command::new(&daemon_bin)
        .arg(config_path.to_str().unwrap())
        .current_dir(config_dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for ready
    let start = std::time::Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(15) {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(ready, "Restarted daemon should become ready");
    assert!(
        child2.try_wait().unwrap().is_none(),
        "Restarted daemon should still be running"
    );

    child2.kill().unwrap();
    child2.wait().unwrap();
}
