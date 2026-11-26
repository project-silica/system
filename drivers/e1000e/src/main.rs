//! The Intel 82574 network driver (e1000e; the 82574 family datasheet,
//! revision 3.4, is what the register numbers below refer to). QEMU's
//! `e1000e` device is an 82574L.
//!
//! It provides `silica.net.Device` for its interface; everything common to
//! network interfaces is `silica_net::service`, and this file is what is
//! the 82574's: its reset, its two descriptor rings and its interrupts.
//! Frames are never touched here: the device reads what it sends from the
//! client's memory and writes what it receives into it, at the addresses
//! the IOMMU gives it.
//!
//! - One receive and one transmit queue of legacy descriptors (16 bytes:
//!   the buffer's address, then the length and the status the device
//!   writes back), [`RING`] of each.
//! - Every receive buffer is 2048 bytes (RCTL.BSIZE, one size for the whole
//!   ring): the device writes up to that much into any of them, so the
//!   interface says so (`Info::receive_bytes`) and the service refuses
//!   smaller buffers. Long frames are off (RCTL.LPE), so a frame never spans
//!   two buffers; the frame check sequence is stripped (RCTL.SECRC) and
//!   added on transmit (IFCS), short frames padded (TCTL.PSP).
//! - MSI-X: receive on entry 0, transmit on 1, everything else (the link)
//!   on 2 (IVAR), or all three causes on entry 0 where fewer are granted.
//! - The Ethernet address is the one the device loaded from its NVM into
//!   receive address 0 (RAL0/RAH0); without one the driver makes a locally
//!   administered one from the device's identity and sets it there.
//!
//! The device is not trusted to keep to its specification: a completion out
//! of order, a frame shorter than an Ethernet header or longer than its
//! buffer, a frame that claims to continue in a second buffer, or registers
//! that read as all ones end the driver, as does a frame not sent in
//! [`TX_TIMEOUT_NS`]; the device manager starts it again, which resets the
//! device, and the client offers its buffers and frames again.
//!
//! In a test image (built with the `harness` feature, never a machine's
//! image) the device faults of `silica_driver::inject` are committed where an
//! 82574 would commit them: `garbage`, the oldest receive descriptor written
//! back done with a length past its buffer and no end of frame; `stuck`, a
//! transmit the device never sees (the transmit tail no longer advanced; on
//! a receive buffer it waits for the next transmit, as a ring would stop
//! receiving altogether); `spurious`, an interrupt with nothing done;
//! `missed`, a look at the rings skipped as if the interrupt never came;
//! `reset`, the device reset (CTRL.RST) as a transmit is handed over.
//!
//! Not yet: checksum and segmentation offloads, more than one queue pair,
//! interrupt moderation (ITR), and a watched receive queue
//! (`Interrupt::watch`).
#![no_std]
#![no_main]

#[cfg(feature = "harness")]
use e1000e::DD;
use e1000e::{DESC, RECEIVE_BYTES, RING, Ring, TX_EOP, TX_IFCS, TX_RS, receive};
use silica_driver::dma::{self, Dma, DmaMemory, Shared};
#[cfg(feature = "harness")]
use silica_driver::inject::{self, Fault};
use silica_driver::irq::{Interrupt, Signals};
use silica_driver::{Device, DeviceError, grant, granted};
use silica_net::device::{Error, Info};
use silica_net::service::{CLIENT, Completions, Refusal, Service, Ticket};
use silica_net::{Op, Request, Status};
use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::serve_events;
use silica_rt::mmio::Mmio;
use silica_rt::sys::Cap;
use silica_rt::{ProcessInfo, println};

silica_rt::main!(main);

// Registers (byte offsets in BAR 0).
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const CTRL_EXT: usize = 0x0018;
const EECD: usize = 0x0010;
const ICR: usize = 0x00C0;
const IMS: usize = 0x00D0;
const IMC: usize = 0x00D8;
const EIAC: usize = 0x00DC;
const IAM: usize = 0x00E0;
const IVAR: usize = 0x00E4;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const RDTR: usize = 0x2820;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const MTA: usize = 0x5200;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const CTRL_EXT_PBA_CLR: u32 = 1 << 31;
/// CTRL_EXT: the queues' interrupts mask themselves (IAM) when sent by MSI-X.
const CTRL_EXT_EIAME: u32 = 1 << 24;
/// EECD: the device has read its NVM (the Ethernet address among it).
const EECD_AUTO_RD: u32 = 1 << 9;
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
/// Collision threshold 15, collision distance 63 (full duplex), as reset.
const TCTL_CT_COLD: u32 = 0x0F << 4 | 0x3F << 12;
/// Inter-packet gap for copper (IPGT 8, IPGR1 8, IPGR2 6).
const TIPG_COPPER: u32 = 8 | 8 << 10 | 6 << 20;
const RAH_AV: u32 = 1 << 31;
/// Interrupt causes (ICR, IMS): the link changed; MSI-X receive queue 0,
/// transmit queue 0, and the other causes.
const INT_LSC: u32 = 1 << 2;
const INT_RXQ0: u32 = 1 << 20;
const INT_TXQ0: u32 = 1 << 22;
const INT_OTHER: u32 = 1 << 24;
/// IVAR: an allocation is valid; transmit write-backs interrupt every time.
const IVAR_VALID: u32 = 0x8;
const IVAR_TX_EVERY: u32 = 1 << 31;

/// The notification bits of the receive and transmit queues and the rest.
const RX: u64 = 2;
const TX: u64 = 4;
const OTHER: u64 = 8;
/// How long the device may take to send a frame.
const TX_TIMEOUT_NS: u64 = 5_000_000_000;
/// How long a reset may take (the datasheet: about 1 ms, then the NVM is read).
const RESET_TIMEOUT_NS: u64 = 100_000_000;
/// How long the NVM may take to load after a reset (Intel's own drivers
/// wait 10 ms).
const NVM_TIMEOUT_NS: u64 = 10_000_000;

fn now() -> u64 {
    silica_rt::clock().now()
}

/// A ring in DMA memory the device reads and writes (it writes each
/// descriptor's status back, a transmit's too: mapped read-only, the IOMMU
/// refused those writes and no transmit was ever seen done).
fn ring(dma: &Dma) -> Result<(DmaMemory, Ring<Ticket>), DeviceError> {
    let memory = dma.memory(12, true)?;
    let ring = Ring::over(memory.shared()).ok_or(DeviceError::Missing("a page for a ring"))?;
    Ok((memory, ring))
}

struct Nic {
    regs: Mmio,
    dma: Dma,
    rx: Ring<Ticket>,
    tx: Ring<Ticket>,
    /// The rings' memory (receive, transmit), kept while the device has it
    /// (and written by an injected `garbage`, in a test image).
    #[cfg_attr(not(feature = "harness"), allow(dead_code))]
    rings: [DmaMemory; 2],
    info: Info,
    _interrupts: Vec<Interrupt>,
    /// What an injected fault left the device doing.
    #[cfg(feature = "harness")]
    injected: Injected,
}

/// What an injected fault left the device doing (test images only).
#[cfg(feature = "harness")]
#[derive(Default)]
struct Injected {
    /// `stuck`: the device no longer sees transmits.
    stuck: bool,
    /// `unplugged`: the device holds transmits while its link is down, as
    /// an 82574 does (QEMU's model sends them nowhere at once).
    unplugged: bool,
}

impl Nic {
    fn give_up(&self, why: DeviceError) -> ! {
        // Where the device and the driver each think the rings are.
        let r = |at: usize| self.regs.read32(at);
        println!(
            "e1000e: receive head {} tail {} (driver {}..{}), transmit head {} tail {} (driver {}..{}), STATUS {:#x}, TCTL {:#x}, RCTL {:#x}",
            r(RDH),
            r(RDT),
            self.rx.next,
            self.rx.tail,
            r(TDH),
            r(TDT),
            self.tx.next,
            self.tx.tail,
            r(STATUS),
            r(TCTL),
            r(RCTL)
        );
        println!("ERROR: e1000e: {why:?}; giving up on the device");
        // Stop both queues: the device then writes nothing more into the
        // client's memory before the next driver resets it.
        self.regs.write32(RCTL, 0);
        self.regs.write32(TCTL, 0);
        silica_rt::exit(2)
    }

    /// The link went down: an 82574 holds what it was given to send until
    /// the link comes back, which a request's timeout would take for a
    /// dead device (every cable pull restarted the driver). The transmit
    /// unit is stopped, every frame it held is answered as dropped, and the
    /// ring starts again empty (82574 datasheet: TDH and TDT written only
    /// while TCTL.EN is clear).
    fn drop_transmits(&mut self, done: &mut Completions<'_>) {
        let tctl = self.regs.read32(TCTL);
        self.regs.write32(TCTL, tctl & !TCTL_EN);
        // The write reaches the device before the ring is taken back.
        let _ = self.regs.read32(STATUS);
        let mut dropped = 0;
        self.tx.drain(|ticket| {
            dropped += 1;
            done(ticket, Err(Status::Io));
        });
        self.regs.write32(TDH, 0);
        self.regs.write32(TDT, 0);
        self.regs.write32(TCTL, tctl);
        if dropped != 0 {
            println!("e1000e: {dropped} frames dropped with the link");
        }
    }

    fn link_up(&self) -> bool {
        self.regs.read32(STATUS) & STATUS_LU != 0
    }
}

impl silica_net::service::Device for Nic {
    type Mapping = Shared;

    fn info(&self) -> Info {
        self.info.clone()
    }

    fn map(&mut self, frame: Cap, bits: u8, writable: bool) -> Result<(u64, Shared), Error> {
        let shared = self.dma.share(frame, bits, writable).map_err(|_| Error::NoRoom)?;
        Ok((shared.address, shared))
    }

    fn unmap(&mut self, mapping: Shared) {
        self.dma.unshare(mapping);
    }

    fn start(&mut self, r: &Request, address: u64, ticket: Ticket) -> Result<(), Refusal> {
        // An injected fault comes due with the nth request offered; from an
        // `unplugged` on, the device holds transmits while its link is down.
        #[cfg(feature = "harness")]
        {
            inject::due();
            if inject::pending(Fault::Unplugged) {
                self.injected.unplugged = true;
            }
        }
        match r.op {
            // The device writes the length back; the buffer is RECEIVE_BYTES
            // (the service checked the request has that many).
            Op::Receive => self.rx.add(address, 0, 0, ticket, now()).then_some(()).ok_or(Refusal::Busy),
            Op::Transmit => {
                // With the link down nothing is sent: the frame is dropped at
                // once, as a cable pulled drops it, rather than held for a
                // timeout that would take the device for dead.
                if !self.info.link_up {
                    return Err(Refusal::Fail(Status::Io));
                }
                let length = u16::try_from(r.length).map_err(|_| Refusal::Fail(Status::Invalid))?;
                if !self.tx.add(address, length, TX_EOP | TX_IFCS | TX_RS, ticket, now()) {
                    return Err(Refusal::Busy);
                }
                // A device that stops seeing transmits, or resets itself as
                // one is handed over (injected).
                #[cfg(feature = "harness")]
                {
                    if inject::pending(Fault::Stuck) {
                        self.injected.stuck = true;
                    }
                    if inject::pending(Fault::Reset) {
                        self.regs.write32(CTRL, self.regs.read32(CTRL) | CTRL_RST);
                    }
                }
                Ok(())
            }
        }
    }

    fn holding(&self) -> usize {
        self.rx.holding() + self.tx.holding()
    }

    fn forget_client(&mut self) -> ! {
        // Buffers given to the receive ring are taken back by resetting the
        // device, which the next start of the driver does.
        println!("e1000e: its last client ended with {} requests in the device; starting again to take them back", self.holding());
        silica_rt::exit_again()
    }

    fn kick(&mut self) {
        // Descriptors are written before the tail that hands them over.
        if self.rx.added || self.tx.added {
            dma::write_barrier();
        }
        if self.rx.added {
            self.regs.write32(RDT, self.rx.tail as u32);
            self.rx.added = false;
        }
        // (An injected `stuck`: the device no longer sees transmits.)
        #[cfg(feature = "harness")]
        let seen = !self.injected.stuck;
        #[cfg(not(feature = "harness"))]
        let seen = true;
        if self.tx.added && seen {
            self.regs.write32(TDT, self.tx.tail as u32);
        }
        self.tx.added = false;
    }

    fn signals(&mut self, bits: u64, done: &mut Completions<'_>, link: &mut dyn FnMut(bool)) {
        // Injected: the oldest receive descriptor written back done, with a
        // length past its buffer and no end of frame; or this interrupt
        // missed (what it reports is found at the next).
        // And `unplugged`: while its link is down the device reports no
        // transmit done, as an 82574 holding its queue does.
        #[cfg(feature = "harness")]
        let (missed, holding) = {
            if self.rx.holding() > 0 && inject::pending(Fault::Garbage) {
                let words = self.rings[0].shared();
                words.write16(self.rx.next * DESC + 8, u16::MAX);
                words.write8(self.rx.next * DESC + 12, DD);
            }
            (bits != 0 && inject::pending(Fault::Missed), self.injected.unplugged && !self.info.link_up)
        };
        #[cfg(not(feature = "harness"))]
        let (missed, holding) = (false, false);
        while let Some(d) = if missed { None } else { self.rx.pop() } {
            match receive(&d) {
                Ok(Ok(length)) => done(d.ticket, Ok(length)),
                Ok(Err(())) => done(d.ticket, Err(Status::Io)),
                Err(broken) => self.give_up(DeviceError::Protocol(broken.why())),
            }
        }
        while let Some(d) = if missed || holding { None } else { self.tx.pop() } {
            done(d.ticket, Ok(0));
        }
        // The queues whose interrupt came were masked when it was sent:
        // unmasked now that they have been looked at. A frame that arrived
        // since left its cause pending, and the unmask sends it at once.
        let unmask = if bits & RX != 0 { INT_RXQ0 } else { 0 } | if bits & TX != 0 { INT_TXQ0 } else { 0 };
        if unmask != 0 {
            self.regs.write32(IMS, unmask);
        }
        if bits & OTHER != 0 {
            // Reading the causes clears them; the link is what STATUS says.
            if self.regs.read32(ICR) == u32::MAX {
                self.give_up(DeviceError::Protocol("the registers read as all ones: the device is gone"));
            }
            let up = self.link_up();
            if up != self.info.link_up {
                self.info.link_up = up;
                println!("e1000e: link {}", if up { "up" } else { "down" });
                if !up {
                    self.drop_transmits(done);
                }
                link(up);
            }
        }
    }

    fn deadline(&self) -> Option<u64> {
        self.tx.oldest().map(|t| t + silica_driver::io_limit(TX_TIMEOUT_NS))
    }

    fn timeout(&mut self, done: &mut Completions<'_>) {
        // What the device finished without an interrupt, then the verdict.
        self.signals(0, done, &mut |_| {});
        if self.deadline().is_some_and(|d| d <= now()) {
            self.give_up(DeviceError::Timeout("a frame the device never sent"));
        }
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: e1000e: {e:?}");
            1
        }
    }
}

/// Reset the device and wait for it to come back.
fn reset(regs: &Mmio) -> Result<(), DeviceError> {
    // Quiet first: no interrupts, no traffic.
    regs.write32(IMC, u32::MAX);
    regs.write32(RCTL, 0);
    regs.write32(TCTL, 0);
    let _ = regs.read32(STATUS);
    regs.write32(CTRL, regs.read32(CTRL) | CTRL_RST);
    silica_driver::settle(RESET_TIMEOUT_NS, "the reset to finish (CTRL.RST to clear)", || match regs.read32(CTRL) {
        u32::MAX => Err(DeviceError::Protocol("the registers read as all ones: the device is gone")),
        c => Ok(c & CTRL_RST == 0),
    })?;
    regs.write32(IMC, u32::MAX);
    let _ = regs.read32(ICR);
    Ok(())
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let regs = device.bar(0).ok_or(DeviceError::Missing("BAR 0, the device's registers"))?;
    if regs.len() < 0x8000 {
        return Err(DeviceError::Missing("BAR 0 of the 82574's 128 KiB"));
    }
    let dma = Dma::new(&device)?;
    reset(&regs)?;

    // The Ethernet address is loaded from the NVM after the reset: read
    // before the load is done, RAL/RAH hold nothing yet, and the driver
    // would replace the burned-in address with one of its own (82574
    // datasheet, EECD.AUTO_RD).
    if silica_driver::settle(NVM_TIMEOUT_NS, "the NVM to load (EECD.AUTO_RD)", || Ok(regs.read32(EECD) & EECD_AUTO_RD != 0)).is_err() {
        println!("e1000e: the NVM did not finish loading within 10 ms; its address may be missing");
    }
    // The Ethernet address: the NVM's, or one made from the device's identity.
    let (low, high) = (regs.read32(RAL0), regs.read32(RAH0));
    let address = if high & RAH_AV != 0 {
        u64::from(low) | u64::from(high & 0xFFFF) << 32
    } else {
        let a = 0x02 | 0x5E << 8 | (device.id as u64) << 16;
        regs.write32(RAL0, a as u32);
        regs.write32(RAH0, (a >> 32) as u32 | RAH_AV);
        a
    };
    // Frames to that address and broadcasts only: no multicast groups.
    for i in 0..128 {
        regs.write32(MTA + 4 * i, 0);
    }
    regs.write32(CTRL, regs.read32(CTRL) | CTRL_SLU);

    // Interrupts: one MSI-X entry per cause where there are three.
    let signals = Signals::new()?;
    let vectors = device.config().msix().map_or(0, |m| m.vectors) as u32;
    let lines = device.lines.end.saturating_sub(device.lines.start);
    let entries = vectors.min(lines);
    if entries == 0 {
        return Err(DeviceError::Missing("an MSI-X interrupt"));
    }
    let mut interrupts = Vec::new();
    let ivar = if entries >= 3 {
        interrupts.push(Interrupt::bind_to(&device, 0, signals.sender(RX)?)?);
        interrupts.push(Interrupt::bind_to(&device, 1, signals.sender(TX)?)?);
        interrupts.push(Interrupt::bind_to(&device, 2, signals.sender(OTHER)?)?);
        IVAR_VALID | (IVAR_VALID | 1) << 8 | (IVAR_VALID | 2) << 16
    } else {
        interrupts.push(Interrupt::bind_to(&device, 0, signals.sender(RX | TX | OTHER)?)?);
        IVAR_VALID | IVAR_VALID << 8 | IVAR_VALID << 16
    };
    regs.write32(IVAR, ivar | IVAR_TX_EVERY);
    // Where an injected spurious interrupt goes.
    #[cfg(feature = "harness")]
    inject::interrupts(signals.sender(RX | TX)?);
    regs.write32(CTRL_EXT, regs.read32(CTRL_EXT) | CTRL_EXT_PBA_CLR | CTRL_EXT_EIAME);
    // A queue's cause clears itself when its message is sent (EIAC), and
    // the queue masks itself then (IAM, with CTRL_EXT.EIAME) until the
    // driver has looked at it (`signals` unmasks it): without the
    // auto-clear the cause would stay set and the device would not
    // interrupt again; without the auto-mask it would interrupt for every
    // frame while the driver is still taking the last ones.
    regs.write32(EIAC, INT_RXQ0 | INT_TXQ0);
    regs.write32(IAM, INT_RXQ0 | INT_TXQ0);

    // The rings, then the queues on.
    let (rx_memory, rx) = ring(&dma)?;
    let (tx_memory, tx) = ring(&dma)?;
    for (base, len, head, tail, memory) in [(RDBAL, RDLEN, RDH, RDT, &rx_memory), (TDBAL, TDLEN, TDH, TDT, &tx_memory)] {
        let at = memory.device_address();
        regs.write32(base, at as u32);
        regs.write32(if base == RDBAL { RDBAH } else { TDBAH }, (at >> 32) as u32);
        regs.write32(len, (RING * DESC) as u32);
        regs.write32(head, 0);
        regs.write32(tail, 0);
    }
    regs.write32(RDTR, 0);
    regs.write32(TIPG, TIPG_COPPER);
    regs.write32(TCTL, TCTL_EN | TCTL_PSP | TCTL_CT_COLD);
    regs.write32(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);
    regs.write32(IMS, INT_RXQ0 | INT_TXQ0 | INT_OTHER | INT_LSC);

    let mut nic = Nic {
        // No offloads yet: its TSO and checksum context descriptors are owed
        // (spec/MILESTONES.md, M4).
        info: Info { address, mtu: 1500, link_up: false, receive_bytes: RECEIVE_BYTES, offloads: 0, segment_bytes: 0 },
        regs,
        dma,
        rx,
        tx,
        rings: [rx_memory, tx_memory],
        _interrupts: interrupts,
        #[cfg(feature = "harness")]
        injected: Injected::default(),
    };
    nic.info.link_up = nic.link_up();
    let a = address.to_le_bytes();
    println!(
        "e1000e: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, MTU 1500, link {}, MSI-X entries {entries}, DMA {}",
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5],
        if nic.info.link_up { "up" } else { "down" },
        if nic.dma.confined() { "confined by the IOMMU" } else { "not confined" },
    );
    let mut service = Service::new(nic, signals.sender(CLIENT)?);
    serve_events(granted(grant::SERVICE), signals.listen(), &mut service)
}
