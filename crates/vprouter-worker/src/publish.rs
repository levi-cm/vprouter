//! Descriptor-relative protected atomic health publication in private /state.
use crate::{Error, Result};
use rustix::fs::{self, FileType, Mode, OFlags};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::{
    io::Write,
    os::fd::{AsFd, OwnedFd},
};
use tokio::sync::oneshot;
use vprouter_core::state::Status;
struct Publication {
    bytes: Vec<u8>,
    ack: oneshot::Sender<Result<()>>,
}
pub(crate) struct Publisher {
    queue: mpsc::SyncSender<Publication>,
    in_flight: Arc<AtomicBool>,
}
struct Writer {
    directory: OwnedFd,
    uid: u32,
    gid: u32,
}
impl Publisher {
    // Namespace-local writer is created only after verified placement. A stalled
    // disk syscall cannot occupy the monitor thread or build an unbounded queue.
    // There is no join in Drop; separate init must bound process termination.
    fn placed(
        placed: &crate::placement::Placed,
        writer: Writer,
        #[cfg(test)] stall: Option<mpsc::Receiver<()>>,
    ) -> Result<Self> {
        placed.check()?;
        let (queue, rx) = mpsc::sync_channel::<Publication>(1);
        let in_flight = Arc::new(AtomicBool::new(false));
        let lane = in_flight.clone();
        std::thread::Builder::new()
            .name("health-writer".into())
            .spawn(move || {
                #[cfg(test)]
                if let Some(stall) = stall {
                    let _ = stall.recv();
                }
                while let Ok(job) = rx.recv() {
                    let result = writer.write(&job.bytes);
                    lane.store(false, Ordering::Release);
                    let _ = job.ack.send(result);
                }
            })
            .map_err(|_| Error::Storage)?;
        placed.check()?;
        Ok(Self { queue, in_flight })
    }
    pub async fn write(&self, status: &Status) -> Result<()> {
        let bytes = serde_json::to_vec(status).map_err(|_| Error::Storage)?;
        if bytes.len() > 16384 {
            return Err(Error::Storage);
        }
        self.in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Storage)?;
        let (ack, rx) = oneshot::channel();
        if self.queue.try_send(Publication { bytes, ack }).is_err() {
            self.in_flight.store(false, Ordering::Release);
            return Err(Error::Storage);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .map_err(|_| Error::Storage)?
            .map_err(|_| Error::Storage)?
    }
    #[cfg(test)]
    pub fn synthetic(directory: OwnedFd) -> Self {
        Self::synthetic_stall(directory, None)
    }
    #[cfg(test)]
    pub fn synthetic_stall(directory: OwnedFd, stall: Option<mpsc::Receiver<()>>) -> Self {
        let s = fs::fstat(&directory).unwrap();
        Self::placed(
            &crate::placement::Placed::synthetic(),
            Writer {
                directory,
                uid: s.st_uid,
                gid: s.st_gid,
            },
            stall,
        )
        .unwrap()
    }
}
impl Writer {
    fn write(&self, encoded: &[u8]) -> Result<()> {
        let st = fs::fstat(&self.directory).map_err(|_| Error::Storage)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory
            || st.st_mode & 0o7777 != 0o700
            || st.st_uid != self.uid
            || st.st_gid != self.gid
        {
            return Err(Error::Storage);
        }
        match fs::statat(
            &self.directory,
            "health.json",
            fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(s)
                if FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
                    && s.st_mode & 0o7777 == 0o600
                    && s.st_uid == self.uid
                    && s.st_gid == self.gid
                    && s.st_nlink == 1 => {}
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(Error::Storage),
        }
        let fd = fs::openat(
            &self.directory,
            ".health.json.pending",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::Storage)?;
        let result = (|| {
            let mut file = std::fs::File::from(fd);
            file.write_all(encoded).map_err(|_| Error::Storage)?;
            fs::fsync(file.as_fd()).map_err(|_| Error::Storage)?;
            fs::renameat(
                &self.directory,
                ".health.json.pending",
                &self.directory,
                "health.json",
            )
            .map_err(|_| Error::Storage)?;
            fs::fsync(&self.directory).map_err(|_| Error::Storage)
        })();
        if result.is_err() {
            let _ = fs::unlinkat(
                &self.directory,
                ".health.json.pending",
                fs::AtFlags::empty(),
            );
        }
        result
    }
}
