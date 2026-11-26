//! The console's text: a grid of character cells and its cursor, and the
//! size a display's mode gives it. A library of its own, so it is tested
//! on the host (`cargo test -p console-grid`); the console draws it.
#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// A character cell's width and height in pixels (the console's font).
pub const CELL: (u32, u32) = (8, 16);
/// The widest and tallest display mode taken, in pixels: past it (no
/// display there is has a side of more than 16384 pixels) the mode is the
/// driver's mistake or its lie, and a grid and a strip sized from it would
/// take more memory than the console has.
pub const MAX_SIDE: u32 = 16384;

/// The grid's columns and rows for a display mode of `width` by `height`
/// pixels, or `None` for one no grid is made for: too small for a cell,
/// or larger than [`MAX_SIDE`].
pub fn grid_size(width: u32, height: u32) -> Option<(u32, u32)> {
    let (columns, rows) = (width / CELL.0, height / CELL.1);
    (columns > 0 && rows > 0 && width <= MAX_SIDE && height <= MAX_SIDE).then_some((columns, rows))
}

/// The text and the cursor.
pub struct Grid {
    columns: u32,
    rows: u32,
    /// Row by row.
    cells: Vec<char>,
    column: u32,
    row: u32,
}

impl Grid {
    pub fn new(columns: u32, rows: u32) -> Grid {
        Grid { columns, rows, cells: vec![' '; columns as usize * rows as usize], column: 0, row: 0 }
    }

    /// Columns and rows of characters.
    pub fn size(&self) -> (u32, u32) {
        (self.columns, self.rows)
    }

    /// The cells, row by row.
    pub fn cells(&self) -> &[char] {
        &self.cells
    }

    /// Make the grid `columns` by `rows` (a display at another size took
    /// the last one's place), keeping the newest text: the rows up to the
    /// cursor's, each cut or padded to the new width, the cursor on the
    /// same text.
    pub fn resize(&mut self, columns: u32, rows: u32) {
        let (oc, nc) = (self.columns as usize, columns as usize);
        let kept = (self.row + 1).min(rows);
        let first = self.row + 1 - kept;
        let mut cells = vec![' '; nc * rows as usize];
        for r in 0..kept as usize {
            let from = &self.cells[(first as usize + r) * oc..][..oc.min(nc)];
            cells[r * nc..r * nc + from.len()].copy_from_slice(from);
        }
        self.cells = cells;
        (self.columns, self.rows) = (columns, rows);
        self.row = kept - 1;
        self.column = self.column.min(columns);
    }

    fn newline(&mut self) {
        self.column = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        let c = self.columns as usize;
        self.cells.copy_within(c.., 0);
        let n = self.cells.len();
        self.cells[n - c..].fill(' ');
    }

    /// Add `text` at the cursor.
    pub fn write(&mut self, text: &str) {
        for ch in text.chars() {
            match ch {
                '\n' => self.newline(),
                '\r' => self.column = 0,
                ch => {
                    if self.column == self.columns {
                        self.newline();
                    }
                    self.cells[(self.row * self.columns + self.column) as usize] = ch;
                    self.column += 1;
                }
            }
        }
    }

    /// Take back the last character of the line being typed.
    pub fn backspace(&mut self) {
        if self.column > 0 {
            self.column -= 1;
            self.cells[(self.row * self.columns + self.column) as usize] = ' ';
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::String;

    fn row(g: &Grid, r: usize) -> String {
        let c = g.size().0 as usize;
        g.cells()[r * c..r * c + c].iter().collect::<String>().trim_end().into()
    }

    /// A mode no display has is no grid: before, the size was multiplied
    /// in 32 bits (a mode of 2^31 by 2^31 pixels overflowed, or asked for
    /// gigabytes) and a zero-sized mode only by luck was refused.
    #[test]
    fn a_display_mode_sizes_the_grid_only_within_bounds() {
        assert_eq!(grid_size(1024, 768), Some((128, 48)));
        assert_eq!(grid_size(MAX_SIDE, MAX_SIDE), Some((2048, 1024)));
        assert_eq!(grid_size(7, 768), None);
        assert_eq!(grid_size(1024, 15), None);
        assert_eq!(grid_size(MAX_SIDE + 8, 768), None);
        assert_eq!(grid_size(1 << 31, 1 << 31), None);
        assert_eq!(grid_size(u32::MAX, u32::MAX), None);
    }

    /// A driver started again at another resolution: the text follows it,
    /// the newest rows kept, each cut or padded to the new width, and
    /// writing goes on where it was.
    #[test]
    fn the_grid_follows_a_display_of_another_size() {
        let mut g = Grid::new(10, 4);
        g.write("one\ntwo\nthree\nfour\nfive");
        assert_eq!((row(&g, 0), row(&g, 3)), ("two".into(), "five".into()));
        // Narrower and shorter: the last two rows, cut.
        g.resize(4, 2);
        assert_eq!((g.size(), row(&g, 0), row(&g, 1)), ((4, 2), "four".into(), "five".into()));
        assert_eq!(g.cells().len(), 8);
        // The cursor at the end of a full row: the next character wraps.
        g.write("!");
        assert_eq!((row(&g, 0), row(&g, 1)), ("five".into(), "!".into()));
        g.backspace();
        g.write("six");
        assert_eq!((row(&g, 0), row(&g, 1)), ("five".into(), "six".into()));
        // Wider and taller: everything kept, the cursor where it was.
        g.resize(20, 6);
        assert_eq!((row(&g, 0), row(&g, 1), row(&g, 2)), ("five".into(), "six".into(), "".into()));
        g.write("teen");
        assert_eq!(row(&g, 1), "sixteen");
    }
}
