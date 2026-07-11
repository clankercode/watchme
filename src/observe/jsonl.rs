use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
pub struct ReadLimits {
    pub max_read_bytes: usize,
    pub max_record_bytes: usize,
    pub max_records: usize,
}
impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_read_bytes: 256 * 1024,
            max_record_bytes: 64 * 1024,
            max_records: 256,
        }
    }
}
#[derive(Debug, Default)]
pub struct JsonlBatch {
    pub records: Vec<serde_json::Value>,
    pub malformed: usize,
    pub oversized: usize,
    pub bytes_read: usize,
}
pub struct JsonlCursor {
    path: PathBuf,
    limits: ReadLimits,
    identity: Option<(u64, u64)>,
    offset: u64,
    partial: Vec<u8>,
}
impl JsonlCursor {
    pub fn new(path: PathBuf, limits: ReadLimits) -> Self {
        Self {
            path,
            limits,
            identity: None,
            offset: 0,
            partial: Vec::new(),
        }
    }
    pub fn read_new(&mut self) -> io::Result<JsonlBatch> {
        let mut file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        let identity = (metadata.dev(), metadata.ino());
        if self.identity != Some(identity) || metadata.len() < self.offset {
            self.offset = 0;
            self.partial.clear();
            self.identity = Some(identity);
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut bytes = Vec::new();
        file.take(self.limits.max_read_bytes as u64)
            .read_to_end(&mut bytes)?;
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        let mut batch = JsonlBatch {
            bytes_read: bytes.len(),
            ..Default::default()
        };
        self.partial.extend_from_slice(&bytes);
        let complete = self
            .partial
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i + 1);
        let tail = self.partial.split_off(complete);
        let lines = std::mem::replace(&mut self.partial, tail);
        for line in lines
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .take(self.limits.max_records)
        {
            if line.len() > self.limits.max_record_bytes {
                batch.oversized += 1;
                continue;
            }
            match serde_json::from_slice(line) {
                Ok(value) => batch.records.push(value),
                Err(_) => batch.malformed += 1,
            }
        }
        if self.partial.len() > self.limits.max_record_bytes {
            self.partial.clear();
            batch.oversized += 1;
        }
        Ok(batch)
    }
}
