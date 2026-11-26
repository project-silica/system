//! The screen as text: a grid of 8 by 16 pixel cells (the console's font),
//! scrolled up when the last row is full. The grid is the console's own;
//! what the display shows is drawn from it, a row at a time, into a strip
//! of the console's memory the display driver reads (`present`). Only rows
//! that differ from what the display was last given are drawn, so typing a
//! character redraws one row and a burst of output scrolls once.

use console_grid::{Grid, grid_size};
use silica_formats::font::{self, HEIGHT, WIDTH};
use silica_protocols::display::device::{Client, Format, Rect};

use silica_rt::alloc::vec::Vec;
use silica_rt::ipc::{Channel, Handle};
use silica_rt::mem::Memory;

/// Light grey text on a near-black background, as 0x00RRGGBB.
const FOREGROUND: u32 = 0x00D8_D8D8;
const BACKGROUND: u32 = 0x0010_1418;
/// A cell the display was never given: drawn whatever the grid holds.
const UNKNOWN: char = '\u{FFFF}';
/// The grid's cells are the font's.
const _: () = assert!(console_grid::CELL.0 as usize == WIDTH && console_grid::CELL.1 as usize == HEIGHT);

/// A display the grid is shown on.
pub struct Display {
    client: Client<Channel, Handle>,
    /// The capability the client calls through: given back with the display.
    _driver: Handle,
    width: u32,
    bgrx: bool,
    /// One row of cells' pixels, `width` a row, lent to the driver.
    strip: Memory,
    /// What the display was last given, cell by cell.
    shown: Vec<char>,
}

impl Display {
    /// Attach a strip of this program's memory to the display `driver` and
    /// size a grid for it.
    pub fn new(driver: Handle) -> Option<(Display, u32, u32)> {
        let mut client = Client::<Channel, Handle>::from(Channel::within(driver.cap(), silica_rt::ipc::DRIVER_CALL_LIMIT));
        let mode = client.mode().ok()?.mode;
        // The mode is the driver's word: one no display has would size the
        // grid and the strip past this program's memory, so it is taken for
        // no display, and said (`grid_size`).
        let Some((columns, rows)) = grid_size(mode.width, mode.height) else {
            silica_rt::println!("console: the display says its mode is {} by {}; not used", mode.width, mode.height);
            return None;
        };
        let bytes = mode.width as usize * HEIGHT * 4;
        let strip = Memory::new(bytes.next_power_of_two().max(4096).trailing_zeros() as u8).ok()?;
        let lent = crate::lend(strip.frame(), silica_rt::sys::Rights::READ, 0)?;
        client.attach(lent).ok()?;
        let shown = silica_rt::alloc::vec![UNKNOWN; columns as usize * rows as usize];
        Some((Display { client, _driver: driver, width: mode.width, bgrx: mode.format == Format::Bgrx, strip, shown }, columns, rows))
    }

    fn pixel(&self, rgb: u32) -> u32 {
        if self.bgrx { rgb } else { (rgb & 0xFF) << 16 | (rgb & 0xFF00) | (rgb >> 16 & 0xFF) }
    }

    /// Bring the display up to date with `grid`. False when the driver
    /// refused: it has ended, and its death notice is on its way.
    pub fn show(&mut self, grid: &Grid) -> bool {
        if grid.cells().len() != self.shown.len() {
            return false;
        }
        let (columns, rows) = grid.size();
        let c = columns as usize;
        let strip = self.strip.shared();
        let (fg, bg) = (self.pixel(FOREGROUND), self.pixel(BACKGROUND));
        for row in 0..rows as usize {
            let line = &grid.cells()[row * c..row * c + c];
            if line == &self.shown[row * c..row * c + c] {
                continue;
            }
            for (column, &ch) in line.iter().enumerate() {
                for (dy, bits) in font::glyph(ch).iter().enumerate() {
                    let base = (dy * self.width as usize + column * WIDTH) * 4;
                    for dx in 0..WIDTH {
                        strip.write32(base + dx * 4, if bits & (0x80 >> dx) != 0 { fg } else { bg });
                    }
                }
            }
            // The pixels right of the last whole cell.
            for dy in 0..HEIGHT {
                for x in c * WIDTH..self.width as usize {
                    strip.write32((dy * self.width as usize + x) * 4, bg);
                }
            }
            let rect = Rect { x: 0, y: (row * HEIGHT) as u32, width: self.width, height: HEIGHT as u32 };
            if self.client.present(rect, 0, self.width).is_err() {
                return false;
            }
            self.shown[row * c..row * c + c].copy_from_slice(line);
        }
        true
    }
}
