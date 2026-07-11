use std::collections::VecDeque;
use std::collections::hash_map::RandomState;
use std::fs::File;
use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
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
    pending: VecDeque<serde_json::Value>,
    discarding: bool,
    generation_guard: Option<GenerationGuard>,
    guard_key: u64,
    rolling_chunk_accumulator: u64,
}
/// Bounded rewrite detection for platforms without a portable file-generation
/// number. It verifies independently sampled regions of the consumed prefix;
/// it cannot guarantee detection if an attacker predicts and preserves every
/// sampled region. The per-cursor keyed position makes that substantially
/// harder without turning each poll into an unbounded prefix reread.
struct GenerationGuard {
    identity: (u64, u64),
    consumed_prefix_len: u64,
    mode: u32,
    samples: Vec<GuardSample>,
    rolling_chunk_accumulator: u64,
}
struct GuardSample {
    position: u64,
    length: usize,
    digest: u64,
}
impl JsonlCursor {
    pub fn new(path: PathBuf, limits: ReadLimits) -> Self {
        let guard_key = keyed_digest(&RandomState::new(), &path);
        Self {
            path,
            limits,
            identity: None,
            offset: 0,
            partial: Vec::new(),
            pending: VecDeque::new(),
            discarding: false,
            generation_guard: None,
            guard_key,
            rolling_chunk_accumulator: 0,
        }
    }
    pub fn read_new(&mut self) -> io::Result<JsonlBatch> {
        let mut file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        let identity = (metadata.dev(), metadata.ino());
        let generation_changed = self
            .generation_guard
            .as_ref()
            .is_some_and(|guard| !guard.matches(&file, &metadata));
        if self.identity != Some(identity) || metadata.len() < self.offset || generation_changed {
            self.offset = 0;
            self.partial.clear();
            self.pending.clear();
            self.discarding = false;
            self.identity = Some(identity);
            self.generation_guard = None;
            self.rolling_chunk_accumulator = 0;
        }
        if !self.pending.is_empty() {
            return Ok(JsonlBatch {
                records: (0..self.limits.max_records)
                    .filter_map(|_| self.pending.pop_front())
                    .collect(),
                ..Default::default()
            });
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(self.limits.max_read_bytes as u64)
            .read_to_end(&mut bytes)?;
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        self.rolling_chunk_accumulator = rolling_digest(self.rolling_chunk_accumulator, &bytes);
        self.generation_guard = GenerationGuard::at_offset(
            &file,
            &metadata,
            self.offset,
            self.guard_key,
            self.rolling_chunk_accumulator,
        )?;
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
        for line in lines.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            if self.discarding {
                self.discarding = false;
                batch.oversized += 1;
                continue;
            }
            if line.len() > self.limits.max_record_bytes {
                batch.oversized += 1;
                continue;
            }
            match serde_json::from_slice(line) {
                Ok(value) => self.pending.push_back(value),
                Err(_) => batch.malformed += 1,
            }
        }
        if self.partial.len() > self.limits.max_record_bytes {
            self.partial.clear();
            self.discarding = true;
        }
        batch
            .records
            .extend((0..self.limits.max_records).filter_map(|_| self.pending.pop_front()));
        Ok(batch)
    }
}

impl GenerationGuard {
    const REGION_BYTES: u64 = 1024;

    fn at_offset(
        file: &File,
        metadata: &std::fs::Metadata,
        offset: u64,
        key: u64,
        rolling_chunk_accumulator: u64,
    ) -> io::Result<Option<Self>> {
        if offset == 0 {
            return Ok(None);
        }
        let region = Self::REGION_BYTES.min(offset);
        let maximum_start = offset - region;
        let keyed_position = key % maximum_start.saturating_add(1);
        let positions = [0, maximum_start / 2, keyed_position, maximum_start];
        let mut samples = Vec::with_capacity(positions.len());
        for position in positions {
            if samples
                .iter()
                .any(|sample: &GuardSample| sample.position == position)
            {
                continue;
            }
            let length = region as usize;
            let mut bytes = vec![0; length];
            file.read_exact_at(&mut bytes, position)?;
            samples.push(GuardSample {
                position,
                length,
                digest: digest(&bytes),
            });
        }
        Ok(Some(Self {
            identity: (metadata.dev(), metadata.ino()),
            consumed_prefix_len: offset,
            mode: metadata.mode(),
            samples,
            rolling_chunk_accumulator,
        }))
    }

    fn matches(&self, file: &File, metadata: &std::fs::Metadata) -> bool {
        let metadata_matches = (metadata.dev(), metadata.ino()) == self.identity
            && metadata.len() >= self.consumed_prefix_len
            && metadata.mode() == self.mode;
        let sample_count = self.samples.len();
        let first_sample = self.rolling_chunk_accumulator as usize % sample_count;
        metadata_matches
            && (0..sample_count).all(|index| {
                let sample = &self.samples[(first_sample + index) % sample_count];
                let mut bytes = vec![0; sample.length];
                file.read_exact_at(&mut bytes, sample.position).is_ok()
                    && digest(&bytes) == sample.digest
            })
    }
}

fn keyed_digest<T: Hash>(state: &RandomState, value: &T) -> u64 {
    state.hash_one(value)
}

fn rolling_digest(previous: u64, bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    previous.hash(&mut hasher);
    for chunk in bytes.chunks(1024) {
        chunk.hash(&mut hasher);
    }
    hasher.finish()
}

fn digest(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}
