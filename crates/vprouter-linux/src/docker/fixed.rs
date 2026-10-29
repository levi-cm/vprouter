//! Fixed GET transport for the isolated no-fork metadata role. This module does
//! not grant admission: callers still need the original native constructor,
//! authenticated private result, actual reap, and complete policy validation.
//!
//! Like the async client, all HTTP bytes live in two bounded,
//! non-growing Zeroizing buffers. No Hyper/Bytes receive allocation is used.
use super::{API, LaunchContainer, LaunchDaemon, LaunchImage, Version, id, version};
use crate::{Error, Result};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{self, RecvFlags, SendFlags},
};
use serde::de::DeserializeOwned;
use std::{collections::VecDeque, os::fd::OwnedFd, time::Duration};
use zeroize::Zeroizing;

use super::http::{WIRE_LIMIT, body};

/// Consumes exactly the already-connected private sockets for one fixed query.
/// It cannot connect, discover a target, execute a callback, or return raw HTTP.
/// Constructing this value alone is NOT proof of a no-fork kernel role.
pub struct Query {
    sockets: VecDeque<OwnedFd>,
    end: f64,
}
impl Query {
    pub fn new(sockets: Vec<OwnedFd>, end: f64, include_image: bool) -> Result<Self> {
        check(end)?;
        if sockets.len() != if include_image { 6 } else { 4 } {
            return Err(Error::DockerProtocol);
        }
        Ok(Self {
            sockets: sockets.into(),
            end,
        })
    }
    fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T> {
        if path.len() > 256 || !path.starts_with('/') || path.bytes().any(|b| b <= 32 || b >= 127) {
            return Err(Error::DockerProtocol);
        }
        check(self.end)?;
        let fd = self.sockets.pop_front().ok_or(Error::DockerProtocol)?;
        // This also marks malformed and failed replies; no parser or Drop can
        // restore the parent's eligibility to fork after a legacy misuse.
        vprouter_core::secret_boundary::mark_ingress();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let mut sent = 0;
        while sent < request.len() {
            check(self.end)?;
            match net::send(
                &fd,
                &request.as_bytes()[sent..],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            ) {
                Ok(0) => return Err(Error::DockerProtocol),
                Ok(n) => sent += n,
                Err(Errno::AGAIN) => wait(&fd, PollFlags::OUT, self.end)?,
                Err(Errno::INTR) => {}
                Err(_) => return Err(Error::DockerUnavailable),
            }
            check(self.end)?;
        }
        // Allocate at the final capacity once. No secret-bearing reallocation
        // or intermediate stack/Bytes payload copy occurs in this transport.
        let mut wire = Zeroizing::new(vec![0u8; WIRE_LIMIT]);
        let mut used = 0;
        loop {
            check(self.end)?;
            if used == wire.len() {
                return Err(Error::TooLarge);
            }
            match net::recv(&fd, &mut wire[used..], RecvFlags::DONTWAIT) {
                Ok((0, _)) => break,
                Ok((n, full)) if n == full => used += n,
                Ok(_) => return Err(Error::TooLarge),
                Err(Errno::AGAIN) => wait(&fd, PollFlags::IN, self.end)?,
                Err(Errno::INTR) => {}
                Err(_) => return Err(Error::DockerProtocol),
            }
            check(self.end)?;
        }
        check(self.end)?;
        let body = body(&wire[..used])?;
        let value = super::managed_json::decode(&body)?;
        check(self.end)?;
        Ok(value)
    }
    fn version(&mut self) -> Result<()> {
        let v: Version = self.get("/version")?;
        if !version(&v.version).is_some_and(|v| v >= (26, 0))
            || !version(&v.api_version).is_some_and(|v| v >= (1, 45))
            || !version(&v.min_api_version).is_some_and(|v| v <= (1, 45))
        {
            return Err(Error::DockerIncompatible);
        }
        Ok(())
    }
    pub fn daemon(&mut self) -> Result<LaunchDaemon> {
        self.version()?;
        self.get(&format!("{API}/info"))
    }
    pub fn image(&mut self, content_id: &str) -> Result<LaunchImage> {
        if !content_id.strip_prefix("sha256:").is_some_and(id) {
            return Err(Error::InvalidInventory);
        }
        self.version()?;
        self.get(&format!("{API}/images/{content_id}/json"))
    }
    pub fn container(&mut self, expected: &str) -> Result<LaunchContainer> {
        if !id(expected) {
            return Err(Error::InvalidInventory);
        }
        self.version()?;
        let c: LaunchContainer = self.get(&format!("{API}/containers/{expected}/json"))?;
        if c.id != expected {
            return Err(Error::InvalidInventory);
        }
        Ok(c)
    }
    pub fn finish(self) -> Result<()> {
        check(self.end)?;
        if !self.sockets.is_empty() {
            return Err(Error::DockerProtocol);
        }
        Ok(())
    }
}
fn check(end: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !now.is_finite() || !end.is_finite() || now <= 0. || now >= end {
        return Err(Error::DockerTimeout);
    }
    Ok(())
}
fn wait(fd: &OwnedFd, flags: PollFlags, end: f64) -> Result<()> {
    loop {
        check(end)?;
        let remaining = end - vprouter_core::health::boot_seconds();
        if !remaining.is_finite() || remaining <= 0. {
            return Err(Error::DockerTimeout);
        }
        let timeout = Timespec::try_from(Duration::from_secs_f64(remaining))
            .map_err(|_| Error::DockerTimeout)?;
        let mut fds = [PollFd::new(fd, flags)];
        let result = poll(&mut fds, Some(&timeout));
        check(end)?;
        match result {
            Ok(0) => return Err(Error::DockerTimeout),
            Ok(_) if fds[0].revents().intersects(flags | PollFlags::HUP) => return Ok(()),
            Ok(_) => return Err(Error::DockerUnavailable),
            Err(Errno::INTR) => {}
            Err(_) => return Err(Error::DockerUnavailable),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_is_exact_and_rejects_trailing_or_ambiguous_data() {
        assert_eq!(
            &*body(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            b"{}"
        );
        assert_eq!(&*body(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n").unwrap(), b"{}");
        for bad in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}x".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(body(bad).is_err());
        }
    }
    #[test]
    fn original_deadline_survives_partial_native_reply() {
        use std::io::{Read, Write};
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = std::thread::spawn(move || {
            let mut request = [0; 512];
            assert!(server.read(&mut request).unwrap() > 0);
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{")
                .unwrap();
            std::thread::sleep(Duration::from_millis(80));
            let _ = server.write_all(b"}");
        });
        let mut query = Query {
            sockets: vec![client.into()].into(),
            end: vprouter_core::health::boot_seconds() + 0.025,
        };
        assert_eq!(
            query.get::<serde_json::Value>("/version"),
            Err(Error::DockerTimeout)
        );
        peer.join().unwrap();
    }
}
