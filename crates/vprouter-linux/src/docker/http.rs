//! Closed Docker HTTP framing; ambiguous or unsupported framing is refused.
use super::LIMIT;
use crate::{Error, Result};
use zeroize::Zeroizing;
pub(super) const HEADER_LIMIT: usize = 16 * 1024;
pub(super) const WIRE_LIMIT: usize = 2 * LIMIT + HEADER_LIMIT;

fn framing(wire: &[u8]) -> Result<(usize, Option<usize>, bool)> {
    let split = wire
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .filter(|n| *n <= HEADER_LIMIT)
        .ok_or(Error::DockerProtocol)?;
    let header_bytes = &wire[..split + 4];
    if header_bytes.iter().enumerate().any(|(i, b)| {
        *b == b'\n' && (i == 0 || header_bytes[i - 1] != b'\r')
            || *b == b'\r' && header_bytes.get(i + 1) != Some(&b'\n')
    }) {
        return Err(Error::DockerProtocol);
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(header_bytes)
        .map_err(|_| Error::DockerProtocol)?;
    if parsed != httparse::Status::Complete(header_bytes.len())
        || response.version != Some(1)
        || !header_bytes.starts_with(b"HTTP/1.1 ")
    {
        return Err(Error::DockerProtocol);
    }
    if response.code != Some(200) {
        return Err(Error::DockerHttpFailure);
    }
    let mut length = None;
    let mut chunked = false;
    for header in response.headers {
        let key = header.name;
        let value = std::str::from_utf8(header.value).map_err(|_| Error::DockerProtocol)?;
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return Err(Error::DockerProtocol);
        }
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || chunked
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Error::DockerProtocol);
            }
            let n: usize = value.parse().map_err(|_| Error::TooLarge)?;
            if n > LIMIT {
                return Err(Error::TooLarge);
            }
            length = Some(n);
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || length.is_some() || !value.eq_ignore_ascii_case("chunked") {
                return Err(Error::DockerProtocol);
            }
            chunked = true;
        } else if key.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(Error::DockerProtocol);
        }
    }
    Ok((split + 4, length, chunked))
}

pub(super) fn body(wire: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (split, length, chunked) = framing(wire)?;
    let payload = &wire[split..];
    let mut output = Zeroizing::new(Vec::with_capacity(LIMIT));
    if let Some(n) = length {
        if payload.len() != n {
            return Err(Error::DockerProtocol);
        }
        output.extend_from_slice(payload);
    } else if chunked {
        let mut at = 0;
        loop {
            let n = payload[at..]
                .windows(2)
                .position(|b| b == b"\r\n")
                .filter(|n| *n > 0 && *n <= 8)
                .ok_or(Error::DockerProtocol)?;
            let text =
                std::str::from_utf8(&payload[at..at + n]).map_err(|_| Error::DockerProtocol)?;
            if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::DockerProtocol);
            }
            let (consumed, count) = match httparse::parse_chunk_size(&payload[at..at + n + 2])
                .map_err(|_| Error::DockerProtocol)?
            {
                httparse::Status::Complete(value) => value,
                httparse::Status::Partial => return Err(Error::DockerProtocol),
            };
            if consumed != n + 2 {
                return Err(Error::DockerProtocol);
            }
            let count: usize = count.try_into().map_err(|_| Error::TooLarge)?;
            at += consumed;
            if count == 0 {
                if &payload[at..] != b"\r\n" {
                    return Err(Error::DockerProtocol);
                }
                break;
            }
            if count > LIMIT - output.len() {
                return Err(Error::TooLarge);
            }
            let end = at.checked_add(count).ok_or(Error::TooLarge)?;
            if end.checked_add(2).is_none_or(|end| end > payload.len())
                || &payload[end..end + 2] != b"\r\n"
            {
                return Err(Error::DockerProtocol);
            }
            output.extend_from_slice(&payload[at..end]);
            at = end + 2;
        }
    } else {
        // The fixed Docker endpoints must delimit their bodies explicitly.
        return Err(Error::DockerProtocol);
    }
    Ok(output)
}

/// Validate headers as soon as they arrive; never wait for an error body.
pub(super) fn headers_complete(wire: &[u8]) -> Result<bool> {
    if wire.windows(4).any(|b| b == b"\r\n\r\n") {
        framing(wire)?;
        return Ok(true);
    }
    if wire.len() > HEADER_LIMIT + 4 {
        return Err(Error::DockerProtocol);
    }
    Ok(false)
}
/// Non-allocating framing progress. Completion is independent of peer EOF.
/// Reject trailers, chunk extensions, close-delimited bodies and duplicate CL,
/// including identical duplicates. These are deliberate closed-policy refusals.
pub(super) fn complete(wire: &[u8]) -> Result<bool> {
    let (split, length, chunked) = framing(wire)?;
    let payload = &wire[split..];
    if let Some(n) = length {
        if payload.len() > n {
            return Err(Error::DockerProtocol);
        }
        return Ok(payload.len() == n);
    }
    if !chunked {
        return Err(Error::DockerProtocol);
    }
    let mut at = 0usize;
    let mut total = 0usize;
    loop {
        let remaining = &payload[at..];
        let Some(n) = remaining.windows(2).position(|b| b == b"\r\n") else {
            if remaining.len() > 9 {
                return Err(Error::DockerProtocol);
            }
            return Ok(false);
        };
        if n == 0 || n > 8 || !remaining[..n].iter().all(u8::is_ascii_hexdigit) {
            return Err(Error::DockerProtocol);
        }
        let text = std::str::from_utf8(&remaining[..n]).map_err(|_| Error::DockerProtocol)?;
        let count = usize::from_str_radix(text, 16).map_err(|_| Error::TooLarge)?;
        at += n + 2;
        if count == 0 {
            return match &payload[at..] {
                b"" | b"\r" => Ok(false),
                b"\r\n" => Ok(true),
                _ => Err(Error::DockerProtocol),
            };
        }
        total = total
            .checked_add(count)
            .filter(|v| *v <= LIMIT)
            .ok_or(Error::TooLarge)?;
        let end = at.checked_add(count).ok_or(Error::TooLarge)?;
        if end.checked_add(2).ok_or(Error::TooLarge)? > payload.len() {
            return Ok(false);
        }
        if &payload[end..end + 2] != b"\r\n" {
            return Err(Error::DockerProtocol);
        }
        at = end + 2;
    }
}
