use crate::{Error, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
    task::JoinHandle,
    time::timeout,
};

pub(crate) const ATTEMPT: Duration = Duration::from_secs(12);
pub(crate) const LOCAL: Duration = Duration::from_secs(2);
const HEADERS: usize = 32;
const HEADER_BUFFER: usize = 8192;
pub(crate) struct Reply {
    pub body: Vec<u8>,
}
/// Dropping/cancelling any request kills its connection task; no detached socket
/// continues a slow request after withdrawal or shutdown.
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) struct Http {
    tx: http1::SendRequest<Full<Bytes>>,
    _driver: Driver,
}
impl Http {
    pub async fn connect<S>(stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, conn) = http1::Builder::new()
            .max_headers(HEADERS)
            .max_buf_size(HEADER_BUFFER)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(http_error)?;
        let driver = Driver(tokio::spawn(async move {
            let _ = conn.await;
        }));
        Ok(Self {
            tx,
            _driver: driver,
        })
    }
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
    pub async fn request(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        body: &[u8],
        limit: usize,
    ) -> Result<Reply> {
        self.tx.ready().await.map_err(http_error)?;
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", host)
            .header("Accept", "application/json")
            .header("Accept-Encoding", "identity")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|_| Error::InvalidConfiguration)?;
        let mut response = self.tx.send_request(request).await.map_err(http_error)?;
        let status = response.status().as_u16();
        // Never follow redirects. Error bodies are neither read nor logged.
        if status != 200 {
            return Err(
                if status == 408 || status == 429 || (500..600).contains(&status) {
                    Error::HttpTransient
                } else {
                    Error::HttpPermanent
                },
            );
        }
        if response
            .headers()
            .get_all("content-encoding")
            .iter()
            .any(|v| v.as_bytes() != b"identity")
        {
            return Err(Error::Malformed);
        }
        if let Some(length) = response.headers().get("content-length") {
            let length = length
                .to_str()
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or(Error::Malformed)?;
            if length > limit {
                return Err(Error::Oversized);
            }
        }
        let mut body = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            let frame = frame.map_err(http_error)?;
            if frame.is_trailers() {
                return Err(Error::Malformed);
            }
            if let Ok(data) = frame.into_data() {
                if data.len() > limit.saturating_sub(body.len()) {
                    return Err(Error::Oversized);
                }
                body.extend_from_slice(&data);
            }
        }
        Ok(Reply { body })
    }
}
fn http_error(e: hyper::Error) -> Error {
    if e.is_parse() || e.is_user() {
        Error::Malformed
    } else if e.is_incomplete_message() || e.is_closed() || e.is_canceled() {
        Error::Transport
    } else {
        Error::Malformed
    }
}
pub(crate) async fn unix_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
    limit: usize,
) -> Result<Reply> {
    timeout(LOCAL, async {
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|_| Error::Transport)?;
        let mut http = Http::connect(stream).await?;
        http.request(method, path, "local-tailscaled.sock", body, limit)
            .await
    })
    .await
    .map_err(|_| Error::Deadline)?
}
