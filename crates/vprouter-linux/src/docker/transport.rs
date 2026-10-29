//! Direct async receive: the future owns all raw response bytes in a fixed
//! initialized wiping allocation, including cancellation and partial errors.
use super::http::{self, WIRE_LIMIT};
use crate::{Error, Result};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use zeroize::Zeroizing;

pub(super) async fn receive(
    socket: &Path,
    path: &str,
    stage: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut stream = timeout(stage, UnixStream::connect(socket))
        .await
        .map_err(|_| Error::DockerTimeout)?
        .map_err(|_| Error::DockerUnavailable)?;
    // Public fixed endpoint/validated IDs only; never interpolate response data.
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut wire = Zeroizing::new(vec![0u8; WIRE_LIMIT]);
    let mut used = 0;
    vprouter_core::secret_boundary::mark_ingress();
    // This single request-stage timer includes sending and receiving headers;
    // partial reads do not restart it. Body has its own single anchored stage.
    timeout(stage, async {
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| Error::DockerProtocol)?;
        loop {
            read(&mut stream, &mut wire, &mut used).await?;
            if http::headers_complete(&wire[..used])? {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| Error::DockerTimeout)??;
    timeout(stage, async {
        while !http::complete(&wire[..used])? {
            read(&mut stream, &mut wire, &mut used).await?;
        }
        http::body(&wire[..used])
    })
    .await
    .map_err(|_| Error::DockerTimeout)?
}
async fn read(stream: &mut UnixStream, wire: &mut [u8], used: &mut usize) -> Result<()> {
    if *used == wire.len() {
        return Err(Error::TooLarge);
    }
    let n = stream
        .read(&mut wire[*used..])
        .await
        .map_err(|_| Error::DockerProtocol)?;
    if n == 0 {
        return Err(Error::DockerProtocol);
    }
    *used += n;
    Ok(())
}
