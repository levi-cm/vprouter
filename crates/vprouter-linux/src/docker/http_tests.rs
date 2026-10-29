mod http {
    use crate::Error;
    use crate::docker::http::*;
    #[test]
    fn progress_matches_body_and_never_accepts_a_truncated_message() {
        for wire in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n",
        ] {
            for end in 0..wire.len() {
                let prefix = &wire[..end];
                if headers_complete(prefix).unwrap() {
                    assert!(!complete(prefix).unwrap());
                }
            }
            assert!(complete(wire).unwrap());
            assert_eq!(&*body(wire).unwrap(), b"{}");
        }
        for wire in [
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Foo: private\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;extension=private\r\n{}\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}",
            "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(complete(wire.as_bytes()).is_err());
            assert!(body(wire.as_bytes()).is_err());
        }
        assert_eq!(
            headers_complete(b"HTTP/1.1 403 Denied\r\nContent-Length: 999\r\n\r\n"),
            Err(Error::DockerHttpFailure)
        );
        assert!(headers_complete(&vec![b'x'; HEADER_LIMIT + 5]).is_err());
        assert_eq!(
            complete(b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n"),
            Err(Error::TooLarge)
        );
    }
}

mod transport {
    use crate::Error;
    use crate::docker::transport::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    // Real local stream, no daemon or privileged socket. Slow partial reads
    // must consume the same stage budget rather than resetting it each turn.
    #[tokio::test(flavor = "current_thread")]
    async fn stages_are_anchored_and_complete_body_does_not_wait_for_eof() {
        for mode in 0..3 {
            let dir = std::env::temp_dir()
                .join(format!("vprouter-http-stage-{}-{mode}", std::process::id()));
            std::fs::create_dir(&dir).unwrap();
            let socket = dir.join("socket");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut req = [0; 1024];
                assert!(s.read(&mut req).await.unwrap() > 0);
                if mode == 0 {
                    for part in [
                        b"HTTP/1.1 ".as_slice(),
                        b"200 OK\r\n",
                        b"Content-Length: ",
                        b"2\r\n\r\n{}",
                    ] {
                        if s.write_all(part).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                } else if mode == 1 {
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                        .await
                        .unwrap();
                    for _ in 0..4 {
                        if s.write_all(b"x").await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                } else {
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
            let result = receive(&socket, "/version", Duration::from_millis(50)).await;
            if mode == 2 {
                assert_eq!(&*result.unwrap(), b"{}");
            } else {
                assert_eq!(result.err(), Some(Error::DockerTimeout));
            }
            server.await.unwrap();
            std::fs::remove_file(socket).unwrap();
            std::fs::remove_dir(dir).unwrap();
        }
    }
}
