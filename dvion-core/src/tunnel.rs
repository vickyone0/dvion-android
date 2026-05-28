use anyhow::Result;
use tokio::sync::mpsc;

const MTU: usize = 1420;

/// Spin up a TUN device (desktop/server only).
#[cfg(not(target_os = "android"))]
pub fn create_tun(
    addr: &str,
) -> Result<(mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tun2::AbstractDevice;

    let mut config = tun2::Configuration::default();
    config
        .address(addr.parse::<std::net::Ipv4Addr>()?)
        .netmask("255.255.255.0".parse::<std::net::Ipv4Addr>()?)
        .mtu(MTU as u16)
        .up();

    let dev = tun2::create_as_async(&config)?;
    let tun_name = dev.tun_name()?;
    let (mut reader, mut writer) = tokio::io::split(dev);

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);

    tokio::spawn(async move {
        let mut buf = vec![0u8; MTU + 4];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => { if out_tx.send(buf[..n].to_vec()).await.is_err() { break; } }
            }
        }
    });
    tokio::spawn(async move {
        while let Some(pkt) = in_rx.recv().await {
            if writer.write_all(&pkt).await.is_err() { break; }
        }
    });

    Ok((out_rx, in_tx, tun_name))
}

/// Wrap an Android VpnService TUN fd using blocking I/O threads bridged to async channels.
/// Blocking threads avoid the need for O_NONBLOCK / AsyncFd entirely.
pub fn create_tun_from_fd(
    fd: std::os::unix::io::RawFd,
) -> Result<(mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>)> {
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;

    let fd_r = unsafe { libc::dup(fd) };
    let fd_w = unsafe { libc::dup(fd) };
    let mut reader = unsafe { std::fs::File::from_raw_fd(fd_r) };
    let mut writer = unsafe { std::fs::File::from_raw_fd(fd_w) };

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);

    // Blocking read thread → async channel
    std::thread::spawn(move || {
        let mut buf = vec![0u8; MTU + 4];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() { break; }
                }
            }
        }
    });

    // Async channel → blocking write thread
    std::thread::spawn(move || {
        while let Some(pkt) = in_rx.blocking_recv() {
            if writer.write_all(&pkt).is_err() { break; }
        }
    });

    Ok((out_rx, in_tx))
}
