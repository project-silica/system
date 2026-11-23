//! The program's log: where [`crate::print!`] writes when the program was
//! started with a log ring ([`crate::slots::LOG`]): every service is, by the
//! service manager, and every driver, by the device manager.
//!
//! The ring (`crate::ring`, [`RECORDS`] records of [`RECORD`] bytes in a
//! frame of 2^[`BITS`] bytes) carries text: each record is a byte of
//! length, then up to 55 bytes. The log service (`silica.log.Log`) takes it
//! out, keeps it, and puts it on the console. Writing never waits: a text
//! that does not fit whole is lost, and the bytes lost are counted and said
//! in the log as soon as there is room again.

use crate::ring::Producer;
use crate::slots;
use crate::sys::{self, ObjectType, Rights};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Bytes in a record: one of length, up to 55 of text.
pub const RECORD: usize = 56;
/// Records in the ring.
pub const RECORDS: u32 = 256;
/// Size of the ring's frame in bits.
pub const BITS: u8 = 14;

struct Log {
    ring: Producer<RECORD>,
    lost: u64,
}

struct Cell(UnsafeCell<Option<Log>>);
// SAFETY: the value is reached only while BUSY is held (`with`).
#[allow(unsafe_code)]
unsafe impl Sync for Cell {}

static LOG: Cell = Cell(UnsafeCell::new(None));
static BUSY: AtomicBool = AtomicBool::new(false);

/// `f` with the log, unless someone has it (a panic while writing): `None`.
fn with<R>(f: impl FnOnce(&mut Option<Log>) -> R) -> Option<R> {
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    // SAFETY: BUSY is held: nobody else has the value.
    #[allow(unsafe_code)]
    let r = f(unsafe { &mut *LOG.0.get() });
    BUSY.store(false, Ordering::Release);
    Some(r)
}

/// At start: take the ring the service manager gave, if it did.
pub(crate) fn start() {
    let Ok(Some(info)) = sys::inspect_slot(slots::SPACE, slots::LOG.0) else { return };
    if info.ty != ObjectType::Frame || info.bits != BITS {
        return;
    }
    let Ok(region) = crate::mem::peer(slots::LOG, BITS, Rights(Rights::READ.0 | Rights::WRITE.0)) else { return };
    if let Some(ring) = Producer::new(region, RECORDS) {
        with(|l| *l = Some(Log { ring, lost: 0 }));
    }
}

/// The text of a record as a reader takes it out of the ring: its length
/// byte is the writer's, so it is clamped to the record.
pub fn text(record: &[u8; RECORD]) -> &[u8] {
    &record[1..1 + (record[0] as usize).min(RECORD - 1)]
}

fn push(ring: &mut Producer<RECORD>, text: &[u8]) {
    for chunk in text.chunks(RECORD - 1) {
        let mut r = [0u8; RECORD];
        r[0] = chunk.len() as u8;
        r[1..1 + chunk.len()].copy_from_slice(chunk);
        let _ = ring.push(&r);
    }
}

/// Write `text` to the log ring: true if the program has one (the text may
/// still have been lost to a full ring), false to write to the console.
pub fn write(text: &[u8]) -> bool {
    with(|l| {
        let Some(log) = l else { return false };
        let need = |n: usize| n.div_ceil(RECORD - 1) as u32;
        if log.lost != 0 {
            // "[<n> bytes of this log were lost: it was full]", built here:
            // formatting through `print!` would come back to this log.
            let mut note = [0u8; 80];
            let head = b"\n[";
            note[..2].copy_from_slice(head);
            let mut digits = [0u8; 20];
            let (mut n, mut k) = (log.lost, 0);
            loop {
                digits[k] = b'0' + (n % 10) as u8;
                k += 1;
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            for i in 0..k {
                note[2 + i] = digits[k - 1 - i];
            }
            let tail = b" bytes of this log were lost: it was full]\n";
            note[2 + k..2 + k + tail.len()].copy_from_slice(tail);
            let len = 2 + k + tail.len();
            if log.ring.room() >= need(len) + need(text.len()) {
                push(&mut log.ring, &note[..len]);
                log.lost = 0;
            }
        }
        if log.lost == 0 && log.ring.room() >= need(text.len()) {
            push(&mut log.ring, text);
        } else {
            log.lost += text.len() as u64;
        }
        if log.ring.wake_needed() {
            let _ = sys::signal(slots::LOG_WAKE);
        }
        true
    })
    .unwrap_or(false)
}

/// The directory of log rings: how the service manager tells the log
/// service which rings it has, without either of them calling the other.
///
/// The service manager waits for the log service (a flush, before a
/// verdict or turning the machine off), so the log service must never wait
/// for the service manager: a call from it, answered only once the manager
/// stops waiting, held both until the wait gave up and lost what the rings
/// still held (2026-11-23, half of 48 loaded boots of the entropy check).
/// So the manager puts each ring's capability in a slot of the log
/// service's own CapSpace (entry `k`'s ring is in the `k`th of the slots it
/// reserved for them), then writes the source's name in entry `k` of this
/// frame, which the log service maps read-only, and then the entry's
/// generation, with release ordering, and signals; the log service reads a
/// generation with acquire ordering, then the name, then takes the ring
/// from its slot. A generation that changed names a new ring for the same
/// source (the program that made the old one was started again).
pub mod directory {
    use crate::mmio::Mmio;

    /// Size of the directory's frame in bits.
    pub const BITS: u8 = 14;
    /// Bytes of an entry: its generation (0: none yet), the name's length,
    /// then the name.
    pub const ENTRY: usize = 128;
    /// Entries in the directory.
    pub const ENTRIES: usize = (1 << BITS) / ENTRY;
    /// The longest name.
    pub const NAME: usize = ENTRY - 8;

    /// Name source `name` in entry `k`, whose ring is in its slot already:
    /// the writer's side. A longer name is cut at [`NAME`] bytes.
    pub fn publish(directory: &Mmio, k: usize, name: &[u8]) {
        let at = k * ENTRY;
        let n = name.len().min(NAME);
        directory.write_bytes(at + 8, &name[..n]);
        directory.write32(at + 4, n as u32);
        let generation = directory.read32(at).wrapping_add(1).max(1);
        directory.store_release32(at, generation);
    }

    /// Entry `k`: its generation (0: nothing there yet) and its name, read
    /// into `name`, whose first `.1` bytes it is. The writer is trusted
    /// (the service manager), and the length is clamped all the same.
    pub fn read(directory: &Mmio, k: usize, name: &mut [u8; NAME]) -> (u32, usize) {
        let at = k * ENTRY;
        let generation = directory.load_acquire32(at);
        if generation == 0 {
            return (0, 0);
        }
        let n = (directory.read32(at + 4) as usize).min(NAME);
        directory.read_bytes(at + 8, &mut name[..n]);
        (generation, n)
    }
}
