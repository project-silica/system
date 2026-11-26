//! The local console (component D20's terminal half): it provides
//! `silica.console.Terminal` to the shell, showing text on the display the
//! device manager offers and echoing it on the serial line, and reading
//! lines from the keyboard it offers. A console port (`silica.console.Port`:
//! a virtual machine's host console) is one more place the terminal is:
//! what is shown goes to it too, and what is typed there is edited into
//! lines as keys are. Any may be missing: without a display the serial
//! line is the screen, without a keyboard or port nothing is read. Any
//! driver may end: the console hears of it (the device manager's death
//! notice), opens the one started in its place, and the screen comes back
//! whole; nothing of the console's is the driver's.
//!
//! The screen is a grid of 8 by 16 pixel cells (the Terminus font), light
//! text on near black; what does not fit scrolls up. The keyboard layout is
//! US English for now; a line is edited with backspace and ends with enter.
#![no_std]
#![no_main]

mod keys;
mod screen;

use console_grid::Grid;
use screen::Display;
use silica_idl_rt::CapList;
use silica_protocols::console::port;
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
/// The console port's driver (bytes arrived), and the device manager (it ended).
const PORT_BYTES: u64 = 8;
const PORT_GONE: u64 = 16;

/// A console port: its ring of what arrives, the ring's memory, and its driver.
struct Port {
    ring: Consumer<8>,
    _memory: Memory,
    driver: port::Client<Channel, Handle>,
    _handle: Handle,
    /// The last byte was a carriage return: a line feed after it ends no
    /// second line.
    after_cr: bool,
}

struct Console {
    devices: manager::Client<Channel, Handle>,
    note: Cap,
    grid: Grid,
    display: Option<Display>,
    /// The ring, its memory, and the driver (its capability).
    keys: Option<(Consumer<8>, Memory, Handle)>,
    port: Option<Port>,
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
        self.send_to_port(text.as_bytes());
    }

    /// Send `bytes` to the console port, if there is one. A line ends with
    /// a carriage return too there: the other end is a terminal.
    fn send_to_port(&mut self, bytes: &[u8]) {
        let Some(p) = &mut self.port else { return };
        let mut out = silica_rt::alloc::vec::Vec::with_capacity(bytes.len() + 8);
        for &b in bytes {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
        for chunk in out.chunks(2048) {
            if p.driver.write(chunk).is_err() {
                // The driver is gone; its death notice brings the next one.
                self.port = None;
                return;
            }
        }
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
            Some(keys::Key::Char(c)) => self.char(c),
            Some(keys::Key::Backspace) => self.backspace(),
            Some(keys::Key::Enter) => self.enter(),
            None => {}
        }
    }

    /// A byte typed at the console port: printable ASCII goes into the
    /// line, backspace and delete take a character out, a carriage return
    /// or line feed (not both) ends the line; the rest is dropped.
    fn port_byte(&mut self, b: u8) {
        let after_cr = self.port.as_mut().is_some_and(|p| core::mem::replace(&mut p.after_cr, b == b'\r'));
        match b {
            b'\r' => self.enter(),
            b'\n' if !after_cr => self.enter(),
            0x08 | 0x7F => self.backspace(),
            0x20..0x7F => self.char(b as char),
            _ => {}
        }
    }

    fn char(&mut self, c: char) {
        if self.line.len() < 1000 {
            self.line.push(c);
            if self.waiting.is_some() {
                let mut b = [0u8; 4];
                self.show(c.encode_utf8(&mut b));
            }
        }
    }

    fn backspace(&mut self) {
        if self.line.pop().is_some() && self.waiting.is_some() {
            self.grid.backspace();
            self.update();
            print!("\u{8} \u{8}");
            self.send_to_port(b"\x08 \x08");
        }
    }

    fn enter(&mut self) {
        let line = core::mem::take(&mut self.line);
        match self.waiting.take() {
            Some(p) => {
                self.show("\n");
                answer_line(p, &line);
            }
            // Typed ahead, up to [`TYPEAHEAD`] lines: past them a line is
            // dropped and said (a stuck key, or a peer at the port, grew the
            // queue without bound, and every line was later run).
            None if self.lines.len() >= TYPEAHEAD => {
                self.show("\nconsole: a line typed ahead was dropped: 16 wait already\n");
            }
            None => self.lines.push_back(line),
        }
    }
}

/// Lines typed before anyone asks, kept for the next reader.
const TYPEAHEAD: usize = 16;

/// Answer a waiting `read_line` with `line`.
fn answer_line(p: Parked, line: &str) {
    let mut buf = [0u8; silica_idl_rt::MAX_MESSAGE];
    let mut caps = CapList::new();
    match (ReadLineReply { line, busy: false }).encode_message(&mut buf, &mut caps) {
        Ok(n) => p.answer(&buf[..n], caps),
        Err(_) => drop(p),
    }
}

impl terminal::Server<Handle> for Console {
    fn write(&mut self, text: &str) -> WriteReply {
        // Printable text only: an escape sequence or a carriage return
        // from a program would move the cursor, rewrite what another
        // wrote, or reach a terminal beyond the console. A line ended for a
        // serial terminal (`\r\n`, as `println!` writes) is ended once: the
        // console ends lines for its port itself.
        let shown = silica_rt::text::printable(text);
        if shown.contains("\r\n") {
            self.show(&shown.replace("\r\n", "\n"));
        } else {
            self.show(&shown);
        }
        WriteReply {}
    }

    fn read_line<'a>(&'a mut self) -> ReadLineReply<'a> {
        match self.lines.pop_front() {
            // The reply borrows the console; the line is kept until the
            // next call in `last`.
            Some(l) => {
                self.show(&l);
                self.show("\n");
                self.line_out = l;
                ReadLineReply { line: &self.line_out, busy: false }
            }
            None => {
                self.wants_wait = true;
                // A parked caller gets the actual line from answer_line.
                // This immediate reply is sent only if we cannot keep it.
                ReadLineReply { line: "", busy: true }
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
            // second reader while the first still waits gets busy.
            self.waiting = parked.take();
            // Typeahead belongs after the reader's prompt, including a
            // partial line typed while the preceding command was running.
            if self.waiting.is_some() && !self.line.is_empty() {
                let typed = core::mem::take(&mut self.line);
                self.show(&typed);
                self.line = typed;
            }
        }
        n
    }

    fn signals(&mut self, bits: u64) {
        if bits & KEYBOARD_GONE != 0 {
            self.keys = keyboard(&mut self.devices, self.note);
            println!("console: the keyboard's driver ended; {}", if self.keys.is_some() { "reading its successor" } else { "no keyboard" });
        }
        if bits & DISPLAY_GONE != 0 {
            self.display = display(&mut self.devices, self.note, &mut self.grid);
            self.update();
            println!(
                "console: the display's driver ended; {}",
                if self.display.is_some() { "showing on its successor" } else { "no display" }
            );
        }
        if bits & PORT_GONE != 0 {
            self.port = console_port(&mut self.devices, self.note);
            println!("console: the console port's driver ended; {}", if self.port.is_some() { "using its successor" } else { "no port" });
        }
        // What arrived at the port, a record (up to 7 bytes) at a time.
        while let Some(p) = &mut self.port {
            match p.ring.pop() {
                Ok(Some(r)) => {
                    for &b in &r[1..1 + (r[0] as usize).min(7)] {
                        self.port_byte(b);
                    }
                }
                Ok(None) => {
                    if self.port.as_mut().is_some_and(|p| p.ring.sleep()) {
                        break;
                    }
                }
                Err(_) => {
                    println!("console: the console port's ring makes no sense; nothing more read from it");
                    self.port = None;
                    break;
                }
            }
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
fn display(devices: &mut manager::Client<Channel, Handle>, note: Cap, grid: &mut Grid) -> Option<Display> {
    let (mut d, columns, rows) = Display::new(open(devices, manager::Class::Display, note, DISPLAY_GONE)?)?;
    // A driver started again may have set another mode: the text
    // follows the display, rather than the display being given up.
    if grid.size() != (columns, rows) {
        grid.resize(columns, rows);
    }
    d.show(grid).then_some(d)
}

/// Arm the empty input ring before the driver sees it. A driver can
/// publish buffered input and signal while its connect call is running.
fn input_ring() -> Option<(Consumer<8>, Memory)> {
    let memory = Memory::new(12).ok()?;
    let mut ring = Consumer::new(memory.shared(), 256)?;
    ring.sleep().then_some((ring, memory))
}

/// The keyboard, connected: its ring and the notification it signals.
fn keyboard(devices: &mut manager::Client<Channel, Handle>, note: Cap) -> Option<(Consumer<8>, Memory, Handle)> {
    let driver = open(devices, manager::Class::Input, note, KEYBOARD_GONE)?;
    let mut kb = input::Client::<Channel, Handle>::from(Channel::within(driver.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
    let (consumer, ring) = input_ring()?;
    kb.connect(lend(ring.frame(), Rights(3), 0)?, lend(note, Rights::WRITE, KEYS)?).ok()?;
    Some((consumer, ring, driver))
}

/// The console port, connected: its ring, and the driver it came from.
fn console_port(devices: &mut manager::Client<Channel, Handle>, note: Cap) -> Option<Port> {
    let handle = open(devices, manager::Class::Port, note, PORT_GONE)?;
    let mut driver = port::Client::<Channel, Handle>::from(Channel::within(handle.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
    let (ring, memory) = input_ring()?;
    driver.connect(lend(memory.frame(), Rights(3), 0)?, lend(note, Rights::WRITE, PORT_BYTES)?).ok()?;
    Some(Port { ring, _memory: memory, driver, _handle: handle, after_cr: false })
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
    let port = console_port(&mut devices, note.cap());
    println!(
        "console: {}{}, {}",
        if display.is_some() { "on the display and the serial line" } else { "on the serial line" },
        if port.is_some() { " and the console port" } else { "" },
        if keys.is_some() { "reading the keyboard" } else { "no keyboard" }
    );
    let mut console = Console {
        devices,
        note: note.cap(),
        grid,
        display,
        keys,
        port,
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
