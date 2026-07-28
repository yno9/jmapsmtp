//! Starting, polling and stopping one relay process.

use std::io::Read as _;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::fixture::Instance;

pub struct Running {
    pub inst: Instance,
    child: Child,
    log_path: std::path::PathBuf,
}

impl Running {
    /// Spawn the relay and block until it answers HTTP.
    pub fn start(inst: Instance) -> Result<Self> {
        let log_path = inst.dir.join("server.log");
        let log = std::fs::File::create(&log_path)?;
        let child = Command::new(inst.dir.join("jmapsmtp"))
            .current_dir(&inst.dir)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            // Left unset deliberately: with no token, RegisterMetrics and
            // RegisterAdmin serve unauthenticated, which is what lets the
            // scenario reach /metrics without inventing a credential.
            .env_remove("METRICS_TOKEN")
            .env_remove("ADMIN_TOKEN")
            .spawn()
            .with_context(|| format!("spawning relay in {}", inst.dir.display()))?;

        let mut running = Running {
            inst,
            child,
            log_path,
        };
        running.wait_ready()?;
        Ok(running)
    }

    fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let url = format!("{}/relay-info", self.inst.base_url());
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "relay exited before becoming ready (status {status}):\n{}",
                    self.log()
                );
            }
            if client.get(&url).send().is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        bail!("relay did not become ready within 20s:\n{}", self.log())
    }

    pub fn log(&self) -> String {
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(&self.log_path) {
            let _ = f.read_to_string(&mut s);
        }
        s
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Ask the OS for a free port by binding to :0 and immediately releasing it.
///
/// Inherently racy, but the alternative — fixed ports — fails outright when
/// two runs overlap or something else already holds the port. The window is a
/// few milliseconds and a collision surfaces as a clean startup failure with
/// the relay's own log attached, not as a confusing diff.
pub fn free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}
