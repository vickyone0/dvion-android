use anyhow::{bail, Context, Result};
use std::process::Command;

pub struct BypassRoute {
    pub server_ip: String,
}

fn default_gw() -> Result<(String, String)> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("ip route")?;
    let text = String::from_utf8_lossy(&out.stdout);

    let mut gw = None;
    let mut dev = None;
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        match tok {
            "via" => gw = it.next().map(str::to_owned),
            "dev" => dev = it.next().map(str::to_owned),
            _ => {}
        }
    }
    match (gw, dev) {
        (Some(g), Some(d)) => Ok((g, d)),
        _ => bail!("cannot parse default route from: {text}"),
    }
}

// Routes all traffic through the TUN using the WireGuard split-route trick:
// two /1 routes cover all IPv4 with higher priority than the default /0,
// so the original default route stays intact and is trivially restored.
pub fn enable_full_tunnel(server_ip: &str, tun: &str) -> Result<BypassRoute> {
    let (gw, iface) = default_gw()?;

    // Keep the VPN server reachable via the real gateway (prevent routing loop)
    ip(&["route", "add", &format!("{server_ip}/32"), "via", &gw, "dev", &iface])?;

    // Override default for all other traffic — roll back bypass route if either fails
    if let Err(e) = ip(&["route", "add", "0.0.0.0/1", "dev", tun]) {
        let _ = ip(&["route", "del", &format!("{server_ip}/32")]);
        return Err(e);
    }
    if let Err(e) = ip(&["route", "add", "128.0.0.0/1", "dev", tun]) {
        let _ = ip(&["route", "del", "0.0.0.0/1", "dev", tun]);
        let _ = ip(&["route", "del", &format!("{server_ip}/32")]);
        return Err(e);
    }

    tracing::info!("full tunnel active — all traffic → {tun} (bypass via {gw})");
    Ok(BypassRoute { server_ip: server_ip.to_owned() })
}

pub fn disable_full_tunnel(bypass: &BypassRoute, tun: &str) {
    let _ = ip(&["route", "del", "0.0.0.0/1",   "dev", tun]);
    let _ = ip(&["route", "del", "128.0.0.0/1",  "dev", tun]);
    let _ = ip(&["route", "del", &format!("{}/32", bypass.server_ip)]);
    tracing::info!("full tunnel disabled — routing restored");
}

pub struct NatGuard {
    iface: String,
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING",
                   "-s", "10.0.0.0/24", "-o", &self.iface, "-j", "MASQUERADE"])
            .status();
        tracing::info!("NAT masquerade removed on {}", self.iface);
    }
}

// Called on the server to masquerade VPN client traffic as the server's public IP.
// Returns a NatGuard that removes the iptables rule when dropped (on shutdown).
pub fn enable_server_nat() -> Result<NatGuard> {
    let (_, iface) = default_gw()?;

    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("enable ip_forward")?;

    let already = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING",
               "-s", "10.0.0.0/24", "-o", &iface, "-j", "MASQUERADE"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !already {
        let s = Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING",
                   "-s", "10.0.0.0/24", "-o", &iface, "-j", "MASQUERADE"])
            .status()
            .context("iptables")?;
        if !s.success() {
            bail!("iptables NAT rule failed");
        }
    }

    tracing::info!("NAT masquerade enabled on {iface}");
    Ok(NatGuard { iface })
}

fn ip(args: &[&str]) -> Result<()> {
    let s = Command::new("ip").args(args).status().context("ip")?;
    if !s.success() {
        bail!("ip {} → exit {s}", args.join(" "));
    }
    Ok(())
}
