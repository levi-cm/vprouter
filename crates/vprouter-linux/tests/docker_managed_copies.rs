//! Allocation observation is deliberately confined to this single-test binary.
//! It detects this canary on exercised free/reallocation paths, not stack,
//! register, allocator-internal or compiler-temporary erasure in general.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use vprouter_linux::{Error, Result, docker::LaunchContainer};
const LIMIT: usize = 1024 * 1024;
#[path = "../src/docker/http.rs"]
mod http;
#[path = "../src/docker/transport.rs"]
mod transport;

static TRACK: AtomicBool = AtomicBool::new(false);
static SCALAR: AtomicBool = AtomicBool::new(false);
static NUMBER_CANARY: [u8; 8] = 0x9b7e23d4a5610fc8u64.to_ne_bytes();
static DIRTY: AtomicUsize = AtomicUsize::new(0);
static CANARY: &[u8] = b"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd";
unsafe extern "C" {
    fn memmem(
        haystack: *const c_void,
        haystacklen: usize,
        needle: *const c_void,
        needlelen: usize,
    ) -> *mut c_void;
}
struct Observed;
fn inspect(p: *mut u8, size: usize) {
    if TRACK.load(Ordering::Relaxed) {
        // Inspect live allocation object bytes via C's unsigned-byte operation;
        // never construct Rust references to arbitrary padding/uninitialized data.
        if !unsafe { memmem(p.cast(), size, CANARY.as_ptr().cast(), CANARY.len()) }.is_null()
            || SCALAR.load(Ordering::Relaxed)
                && !unsafe {
                    memmem(
                        p.cast(),
                        size,
                        NUMBER_CANARY.as_ptr().cast(),
                        NUMBER_CANARY.len(),
                    )
                }
                .is_null()
        {
            DIRTY.fetch_add(1, Ordering::Relaxed);
        }
    }
}
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        inspect(p, l.size());
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        inspect(p, l.size());
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOCATOR: Observed = Observed;

#[test]
fn docker_partial_decode_releases_only_wiped_managed_copies() {
    // Calibrate the observer with an intentionally unwiped owned copy.
    DIRTY.store(0, Ordering::Relaxed);
    TRACK.store(true, Ordering::SeqCst);
    drop(std::hint::black_box(CANARY.to_vec()));
    TRACK.store(false, Ordering::SeqCst);
    assert_eq!(DIRTY.load(Ordering::Relaxed), 1);
    DIRTY.store(0, Ordering::Relaxed);
    SCALAR.store(true, Ordering::Relaxed);
    TRACK.store(true, Ordering::SeqCst);
    drop(std::hint::black_box(Box::new(0x9b7e23d4a5610fc8u64)));
    TRACK.store(false, Ordering::SeqCst);
    SCALAR.store(false, Ordering::Relaxed);
    assert_eq!(
        DIRTY.load(Ordering::Relaxed),
        1,
        "observer must cover eight-byte allocations"
    );
    let cases: &[&[u8]] = &[
        br#"{"Id":"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd","Image":17}"#,
        br#"{"HostConfig":{"NetworkMode":"none","DOCKER_PRIVATE_PAYLOAD_9bc7a1fd":"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd"}}"#,
        br#"{"Config":{"Labels":{"label":"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd","label":"replacement"},"User":"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd","Volumes":null},"Id":17}"#,
        br#"{"Id":"\u0044OCKER_PRIVATE_PAYLOAD_9bc7a1fd","Image":17}"#,
        br#"{"Env":["\u0044OCKER_PRIVATE_PAYLOAD_9bc7a1fd"],"Id":"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd","Image":"\uD800x"}"#,
        b"{\"Id\":\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\",\"Image\":\"\xff\"}",
    ];
    let mut dirty = [0; 6];
    for (i, bytes) in cases.iter().enumerate() {
        DIRTY.store(0, Ordering::Relaxed);
        TRACK.store(true, Ordering::SeqCst);
        let value = LaunchContainer::decode_json(bytes);
        let failed = value.is_err();
        drop(value);
        TRACK.store(false, Ordering::SeqCst);
        dirty[i] = DIRTY.load(Ordering::Relaxed);
        assert!(failed);
    }
    assert_eq!(dirty, [0; 6], "managed input copies survived Drop");
    // Inputs are constructed before tracking: their caller-owned bytes are not
    // parser-managed copies. This complete HostConfig reaches flatten replay.
    let mut full = serde_json::json!({"Id":"id","Image":"image","State":{"Running":true,"Paused":false,"Restarting":false,"Dead":false,"Pid":2,"StartedAt":"time"},"Config":{"Labels":{},"User":"","Volumes":null},"HostConfig":{
        "NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"PidMode":"","UsernsMode":"","CgroupnsMode":"private","IpcMode":"private","UTSMode":"","CapAdd":null,"CapDrop":null,"SecurityOpt":null,"Binds":null,"Devices":[],"DeviceRequests":null,"DeviceCgroupRules":null,"VolumesFrom":null,"GroupAdd":null,"CgroupParent":"","Runtime":"runc","MaskedPaths":null,"ReadonlyPaths":null,
        "DOCKER_PRIVATE_PAYLOAD_9bc7a1fd":{"nested":["DOCKER_PRIVATE_PAYLOAD_9bc7a1fd"]}},"Mounts":[],"AppArmorProfile":"","ProcessLabel":"","MountLabel":""});
    let valid = serde_json::to_vec(&full).unwrap();
    full["HostConfig"]["NumericSecret"] = serde_json::json!(0x9b7e23d4a5610fc8u64);
    let scalar = serde_json::to_vec(&full).unwrap();
    full["HostConfig"]
        .as_object_mut()
        .unwrap()
        .remove("NumericSecret");
    full["Mounts"] = serde_json::json!([{"Type":"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd","Source":13}]);
    let partial = serde_json::to_vec(&full).unwrap();
    let escaped = String::from_utf8(valid.clone())
        .unwrap()
        .replace(
            "DOCKER_PRIVATE_PAYLOAD_9bc7a1fd",
            "\\u0044OCKER_PRIVATE_PAYLOAD_9bc7a1fd",
        )
        .into_bytes();
    let duplicate_unknown = String::from_utf8(valid.clone()).unwrap().replace(
        "\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\":{", "\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\":\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\",\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\":{").into_bytes();
    let bad_type = String::from_utf8(valid.clone())
        .unwrap()
        .replace(
            "\"Running\":true",
            "\"Running\":\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\"",
        )
        .into_bytes();
    let duplicate_required = String::from_utf8(valid.clone())
        .unwrap()
        .replace(
            "\"Id\":\"id\"",
            "\"Id\":\"id\",\"Id\":\"DOCKER_PRIVATE_PAYLOAD_9bc7a1fd\"",
        )
        .into_bytes();
    for (input, success) in [
        (&valid, true),
        (&partial, false),
        (&escaped, true),
        (&duplicate_unknown, true),
        (&bad_type, false),
        (&duplicate_required, false),
    ] {
        DIRTY.store(0, Ordering::Relaxed);
        TRACK.store(true, Ordering::SeqCst);
        let value = LaunchContainer::decode_json(input);
        let accepted = value.is_ok();
        drop(value);
        TRACK.store(false, Ordering::SeqCst);
        assert_eq!(accepted, success);
        assert_eq!(
            DIRTY.load(Ordering::Relaxed),
            0,
            "flatten/error copies survived Drop"
        );
    }

    DIRTY.store(0, Ordering::Relaxed);
    SCALAR.store(true, Ordering::Relaxed);
    TRACK.store(true, Ordering::SeqCst);
    let scalar_value = LaunchContainer::decode_json(&scalar);
    let scalar_ok = scalar_value.is_ok();
    drop(scalar_value);
    TRACK.store(false, Ordering::SeqCst);
    SCALAR.store(false, Ordering::Relaxed);
    assert!(scalar_ok);
    assert_eq!(
        DIRTY.load(Ordering::Relaxed),
        0,
        "dynamic numeric/flatten copies survived Drop"
    );

    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        use tokio::{io::{AsyncReadExt,AsyncWriteExt}, net::UnixListener, time::{Duration,timeout}};
        for cancel in [false,true] {
            let socket = std::env::temp_dir().join(format!("vprouter-docker-copy-{}-{cancel}.sock",std::process::id()));
            let listener = UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream,_) = listener.accept().await.unwrap();
                let mut request = [0;1024];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nDOCKER_PRIVATE_PAYLOAD_9bc7a1fd").await.unwrap();
                if cancel { tokio::time::sleep(Duration::from_millis(70)).await; }
            });
            DIRTY.store(0,Ordering::Relaxed);
            TRACK.store(true,Ordering::SeqCst);
            let value = timeout(Duration::from_millis(30),transport::receive(&socket,"/version",Duration::from_millis(100))).await;
            let failed = match &value { Err(_) => true, Ok(v) => v.is_err() };
            drop(value);
            // Let an old spawned HTTP driver actually observe abortion too.
            tokio::task::yield_now().await;
            TRACK.store(false,Ordering::SeqCst);
            let count = DIRTY.load(Ordering::Relaxed);
            server.await.unwrap();
            std::fs::remove_file(socket).unwrap();
            assert!(failed);
            assert_eq!(count,0,"HTTP cancellation/truncation released an unwiped receive copy");
        }
    });
}
