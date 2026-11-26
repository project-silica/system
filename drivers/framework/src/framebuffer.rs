//! Copying rectangles from a client's byte-addressed pixel buffer to a
//! linear framebuffer. Both buffers use four bytes per pixel.

use silica_rt::mmio::Mmio;

/// The exclusive end of a rectangle of pixels, including row padding.
pub fn byte_end(offset: u64, width: u32, height: u32, stride: u32) -> Option<u64> {
    if width == 0 || height == 0 {
        return Some(offset);
    }
    if stride < width {
        return None;
    }
    let pixels = (u64::from(height) - 1) * u64::from(stride) + u64::from(width);
    offset.checked_add(pixels.checked_mul(4)?)
}

/// Copy a row between ranges already checked to contain all its pixels.
/// The framebuffer starts at a pixel boundary. Clients can place their
/// source pixels at any byte offset.
#[inline]
pub fn copy_row(to: &Mmio, dst: usize, from: &Mmio, src: usize, width: u32) {
    let bytes = width as usize * 4;
    let source = from.addr() + src;
    if source.is_multiple_of(8) && (to.addr() + dst).is_multiple_of(8) {
        for i in (0..bytes & !7).step_by(8) {
            to.write64(dst + i, from.read64(src + i));
        }
        if !bytes.is_multiple_of(8) {
            to.write32(dst + bytes - 4, from.read32(src + bytes - 4));
        }
    } else if source.is_multiple_of(4) {
        for i in (0..bytes).step_by(4) {
            to.write32(dst + i, from.read32(src + i));
        }
    } else {
        for i in (0..bytes).step_by(4) {
            let mut pixel = [0; 4];
            from.read_bytes(src + i, &mut pixel);
            to.write32(dst + i, u32::from_ne_bytes(pixel));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_padding_and_last_pixel_must_fit_the_address_range() {
        assert_eq!(byte_end(1, 2, 3, 4), Some(41));
        assert_eq!(byte_end(1, 3, 1, 2), None);
        assert_eq!(byte_end(u64::MAX, 0, 8, 0), Some(u64::MAX));
        assert_eq!(byte_end(u64::MAX - 3, 1, 1, 1), None);
        assert_eq!(byte_end(0, u32::MAX, u32::MAX, u32::MAX), None);
    }

    #[test]
    fn packed_pixels_copy_whole_at_every_byte_offset() {
        let mut source = [0u64; 4];
        let mut screen = [0u64; 4];
        // SAFETY: both arrays are disjoint, live, aligned storage accessed
        // only through these views for the duration of the test.
        #[allow(unsafe_code)]
        let (from, to) = unsafe { (Mmio::new(source.as_mut_ptr() as usize, 32), Mmio::new(screen.as_mut_ptr() as usize, 32)) };
        for i in 0..32 {
            from.write8(i, i as u8);
        }
        for src in 0..8 {
            for dst in [0, 4] {
                to.write_bytes(0, &[0xff; 32]);
                copy_row(&to, dst, &from, src, 3);
                for i in 0..32 {
                    let expected = if (dst..dst + 12).contains(&i) { (src + i - dst) as u8 } else { 0xff };
                    assert_eq!(to.read8(i), expected);
                }
            }
        }
    }
}
