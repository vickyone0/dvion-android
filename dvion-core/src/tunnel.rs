use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const MTU: usize = 1420;

/// Spin up a TUN device (desktop/server only).
#[cfg(feature = "cli")]
pub fn create_tun(
    addr: &str,
) -> Result<(mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>, String)> {
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

/// Wrap an existing TUN fd from Android's VpnService.
pub fn create_tun_from_fd(
    fd: std::os::unix::io::RawFd,
) -> Result<(mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>)> {
    use std::os::unix::io::FromRawFd;

    // dup so the original fd stays valid when File takes ownership
    let dup_fd = unsafe { libc::dup(fd) };
    let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };

    // Use tokio AsyncFd to drive the raw fd as an async reader/writer
    use tokio::io::unix::AsyncFd;
    let afd = std::sync::Arc::new(AsyncFd::new(file)?);

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);

    // reader task
    let afd_r = std::sync::Arc::clone(&afd);
    tokio::spawn(async move {
        let mut buf = vec![0u8; MTU + 4];
        loop {
            let mut guard = match afd_r.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };
            match guard.try_io(|inner| {
                use std::io::Read;
                inner.get_ref().read(&mut buf)
            }) {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    guard.clear_ready();
                    if out_tx.send(buf[..n].to_vec()).await.is_err() { break; }
                }
                Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }
                Ok(Err(_)) => break,
            }
        }
    });

    // writer task
    tokio::spawn(async move {
        while let Some(pkt) = in_rx.recv().await {
            let mut guard = match afd.writable().await {
                Ok(g) => g,
                Err(_) => break,
            };
            let _ = guard.try_io(|inner| {
                use std::io::Write;
                inner.get_ref().write_all(&pkt)
            });
        }
    });

    Ok((out_rx, in_tx))
}
