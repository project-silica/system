//! The local console (component D20's terminal half): it provides
//! `silica.console.Terminal` to the shell, showing text on the display the
//! device manager offers and echoing it on the serial line, and reading
//! lines from the keyboard it offers. Either may be missing: without a
//! display the serial line is the screen, without a keyboard nothing is
//! read. Either driver may end: the console hears of it (the device
//! manager's death notice), opens the one started in its place, and the
//! screen comes back whole; nothing of the console's is the driver's.
//!
//! The screen is a grid of 8 by 16 pixel cells (the Terminus font), light
//! text on near black; what does not fit scrolls up. The keyboard layout is
//! US English for now; a line is edited with backspace and ends with enter.
#![no_std]
#![no_main]

mod font;
mod keys;
mod screen;

use screen::{Display, Grid};
use silica_idl_rt::CapList;
use silica_protocols::console::terminal::{self, ReadLineReply, SizeReply, WriteReply};
use silica_protocols::device::manager;
use silica_protocols::input::device as input;
use silica_ring::Consumer;
use silica_rt::alloc::collections::VecDeque;
use silica_rt::alloc::string::String;
use silica_rt::ipc::{Channel, Handle, Parked, Waiting, serve_parked};
use silica_rt::mem::{Memory, Object};
use silica_rt::sys::{self, Cap, ObjectType, Rights};
use silica_rt::{ProcessInfo, print, println, slots};

silica_rt::main!(main);

/// Grants: 0 its endpoint, 1 the device manager.
const ENDPOINT: Cap = Cap(slots::FIRST_GRANT);
const DEVICES: Cap = Cap(slots::FIRST_GRANT + 1);

/// The console's notification, by who signals it: the keyboard's driver
/// (records added), and the device manager (the keyboard's, or the
/// display's, driver ended).
const KEYS: u64 = 1;
const KEYBOARD_GONE: u64 = 2;
const DISPLAY_GONE: u64 = 4;

struct Console {
    devices: manager::Client<Channel, Handle>,
    note: Cap,
    grid: Grid,
    display: Option<Display>,
    /// The ring, its memory, and the driver (its capability).
    keys: Option<(Consumer<8>, Memory, Handle)>,
    modifiers: keys::Modifiers,
    line: String,
    lines: VecDeque<String>,
    /// A `read_line` waiting for the next line.
    waiting: Option<Parked>,
    wants_wait: bool,
    /// The line `read_line` answers with now (its reply borrows it).
    line_out: String,
}

impl Console {
    /// Show `text`: on the display, then on the serial line, so a line on
    /// the serial line is on the screen already.
    fn show(&mut self, text: &str) {
        self.grid.write(text);
        self.update();
        print!("{text}");
    }

    /// Bring the display up to date with the grid.
    fn update(&mut self) {
        if let Some(d) = &mut self.display
            && !d.show(&self.grid)
        {
            // The driver is gone; its death notice brings the next one.
            self.display = None;
        }
    }

    /// A key went down: edit the line, or end it.
    fn key(&mut self, usage: u16, down: bool) {
        match self.modifiers.key(usage, down) {
            Some(keys::Key::Char(c)) => {
                if self.line.len() < 1000 {
                    self.line.push(c);
                    let mut b = [0u8; 4];
                    self.show(c.encode_utf8(&mut b));
                }
            }
            Some(keys::Key::Backspace) => {
                if self.line.pop().is_some() {
                    self.grid.backspace();
                    self.update();
                    print!("\u{8} \u{8}");
                }
            }
            Some(keys::Key::Enter) => {
                self.show("\n");
                let line = core::mem::take(&mut self.line);
                match self.waiting.take() {
                    Some(p) => answer_line(p, &line),
                    None => self.lines.push_back(line),
                }
            }
            None => {}
        }
    }
}

/// Answer a waiting `read_line` with `line`.
fn answer_line(p: Parked, line: &str) {
    let mut buf = [0u8; silica_idl_rt::MAX_MESSAGE];
    let mut caps = CapList::new();
    match (ReadLineReply { line }).encode_message(&mut buf, &mut caps) {
        Ok(n) => p.answer(&buf[..n], caps),
        Err(_) => drop(p),
    }
}

impl terminal::Server<Handle> for Console {
    fn write(&mut self, text: &str) -> WriteReply {
        self.show(text);
        WriteReply {}
    }

    fn read_line<'a>(&'a mut self) -> ReadLineReply<'a> {
        match self.lines.pop_front() {
            // The reply borrows the console; the line is kept until the
            // next call in `last`.
            Some(l) => {
                self.line_out = l;
                ReadLineReply { line: &self.line_out }
            }
            None => {
                self.wants_wait = true;
                ReadLineReply { line: "" }
            }
        }
    }

    fn size(&mut self) -> SizeReply {
        let (columns, rows) = self.grid.size();
        SizeReply { columns, rows }
    }
}

impl Waiting for Console {
    fn call(
        &mut self,
        _badge: u64,
        request: &[u8],
        caps: CapList<Handle>,
        reply: &mut [u8],
        reply_caps: &mut CapList<Handle>,
        parked: &mut Option<Parked>,
    ) -> usize {
        self.wants_wait = false;
        let n = terminal::dispatch(self, request, caps, reply, reply_caps);
        if self.wants_wait && !self.waiting.as_ref().is_some_and(Parked::waiting) {
            // Kept until the next line. A reader whose caller has gone (a
            // shell restarted under its call) gives way to the new one; a
            // second reader while the first still waits gets an empty line.
            self.waiting = parked.take();
        }
        n
    }

    fn signals(&mut self, bits: u64) {
        if bits & KEYBOARD_GONE != 0 {
            self.keys = keyboard(&mut self.devices, self.note);
            println!("console: the keyboard's driver ended; {}", if self.keys.is_some() { "reading its successor" } else { "no keyboard" });
        }
        if bits & DISPLAY_GONE != 0 {
            self.display = display(&mut self.devices, self.note, &self.grid);
            self.update();
            println!(
                "console: the display's driver ended; {}",
                if self.display.is_some() { "showing on its successor" } else { "no display" }
            );
        }
        loop {
            let Some((ring, _, _)) = &mut self.keys else { return };
            match ring.pop() {
                Ok(Some(r)) => self.key(u16::from_le_bytes([r[0], r[1]]), r[2] != 0),
                Ok(None) => {
                    if self.keys.as_mut().is_some_and(|(ring, _, _)| ring.sleep()) {
                        return;
                    }
                }
                Err(_) => {
                    println!("console: the keyboard's ring makes no sense; no more keys");
                    self.keys = None;
                    return;
                }
            }
        }
    }
}

/// A capability derived from `cap` with `rights` and `badge`, to give away.
pub(crate) fn lend(cap: Cap, rights: Rights, badge: u64) -> Option<Handle> {
    let slot = silica_rt::ipc::free_slot()?;
    if sys::cap_derive(slots::SPACE, slot, cap, rights, badge).is_err() {
        silica_rt::ipc::release_slot(slot);
        return None;
    }
    Some(Handle::new(Cap(slot)))
}

/// The first device of `class`, opened: its driver, which signals `gone`
/// on `note` when it ends.
fn open(devices: &mut manager::Client<Channel, Handle>, class: manager::Class, note: Cap, gone: u64) -> Option<Handle> {
    let id = devices.list(class).ok()?.devices.iter().next()?.id;
    Some(devices.open(id, Some(lend(note, Rights::WRITE, gone)?)).ok()?.driver)
}

/// The display, attached, showing `grid` whole.
fn display(devices: &mut manager::Client<Channel, Handle>, note: Cap, grid: &Grid) -> Option<Display> {
    let (mut d, _, _) = Display::new(open(devices, manager::Class::Display, note, DISPLAY_GONE)?)?;
    d.show(grid).then_some(d)
}

/// The keyboard, connected: its ring and the notification it signals.
fn keyboard(devices: &mut manager::Client<Channel, Handle>, note: Cap) -> Option<(Consumer<8>, Memory, Handle)> {
    let driver = open(devices, manager::Class::Input, note, KEYBOARD_GONE)?;
    let mut kb = input::Client::<Channel, Handle>::from(Channel::new(driver.cap()));
    let ring = Memory::new(12).ok()?;
    kb.connect(lend(ring.frame(), Rights(3), 0)?, lend(note, Rights::WRITE, KEYS)?).ok()?;
    let region = ring.shared();
    let mut consumer = Consumer::new(region, 256)?;
    let _ = consumer.sleep();
    Some((consumer, ring, driver))
}

fn main(_info: &'static ProcessInfo) -> i64 {
    let mut devices = manager::Client::<Channel, Handle>::from(Channel::new(DEVICES));
    let Ok(note) = Object::new(ObjectType::Notification, 0) else {
        println!("ERROR: console: no memory");
        return 1;
    };
    // The grid is the display's size, or a serial terminal's.
    let first = open(&mut devices, manager::Class::Display, note.cap(), DISPLAY_GONE).and_then(Display::new);
    let (display, grid) = match first {
        Some((d, columns, rows)) => (Some(d), Grid::new(columns, rows)),
        None => (None, Grid::new(80, 25)),
    };
    let keys = keyboard(&mut devices, note.cap());
    println!(
        "console: {}, {}",
        if display.is_some() { "on the display and the serial line" } else { "on the serial line" },
        if keys.is_some() { "reading the keyboard" } else { "no keyboard" }
    );
    let mut console = Console {
        devices,
        note: note.cap(),
        grid,
        display,
        keys,
        modifiers: keys::Modifiers::default(),
        line: String::new(),
        lines: VecDeque::new(),
        waiting: None,
        wants_wait: false,
        line_out: String::new(),
    };
    console.update();
    serve_parked(ENDPOINT, note.cap(), &mut console)
}
