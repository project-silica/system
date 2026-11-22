//! The display driver for the framebuffer the firmware set up (GOP): the
//! mode stays the one the firmware chose. It provides
//! `silica.display.Device`: the client draws in a frame of its own and
//! presents rectangles of it, which this driver copies into the
//! framebuffer.
//!
//! The device manager starts it for a VGA-compatible display controller
//! whose memory holds the firmware's framebuffer, and says where in its
//! arguments: 5 the width (low half) and height (high half) in pixels, 6
//! the pixels per row (low half) and the format (high half: 1 RGBX, 2
//! BGRX), 7 the BAR holding the framebuffer, which starts at its first byte.
#![no_std]
#![no_main]

use silica_driver::{Device, DeviceError, grant, granted};
use silica_idl_rt::CapList;
use silica_protocols::display::device::{self, AttachReply, Error, Format, Mode, ModeReply, PresentReply, Rect};
use silica_rt::ipc::{Handle, serve};
use silica_rt::mem;
use silica_rt::mmio::Mmio;
use silica_rt::sys::{self, Rights};
use silica_rt::{ProcessInfo, println, slots};

silica_rt::main!(main);

struct Display {
    mode: Mode,
    /// Pixels from the start of one row of the framebuffer to the next.
    stride: u32,
    framebuffer: Mmio,
    /// The client's frame and where it is mapped (read only, among lent
    /// memory: a client that takes it back leaves zeros, not a fault).
    attached: Option<(Handle, Mmio)>,
}

impl device::Server<Handle> for Display {
    fn mode(&mut self) -> ModeReply {
        ModeReply { mode: self.mode.clone() }
    }

    fn attach(&mut self, pixels: Handle) -> Result<AttachReply, Error> {
        // The last frame goes: deleting its capability unmaps it.
        self.attached = None;
        let bits = match sys::inspect_slot(slots::SPACE, pixels.cap().0) {
            Ok(Some(s)) if s.ty == sys::ObjectType::Frame => s.bits,
            _ => return Err(Error::BadMemory),
        };
        // Among lent memory: taking it back leaves zeros, never a fault.
        let region = mem::peer(pixels.cap(), bits, Rights::READ).map_err(|_| Error::BadMemory)?;
        self.attached = Some((pixels, region));
        Ok(AttachReply {})
    }

    fn present(&mut self, rect: Rect, offset: u64, stride: u32) -> Result<PresentReply, Error> {
        let Some((_, from)) = &self.attached else { return Err(Error::NotAttached) };
        let Rect { x, y, width, height } = rect;
        let (x, y, w, h, stride) = (x as u64, y as u64, width as u64, height as u64, stride as u64);
        if w == 0 || h == 0 {
            return Ok(PresentReply {});
        }
        let on_screen = x + w <= self.mode.width as u64 && y + h <= self.mode.height as u64;
        let last = offset.checked_add(((h - 1) * stride + w) * 4);
        if !on_screen || stride < w || last.is_none_or(|l| l > from.len() as u64) {
            return Err(Error::Outside);
        }
        let to = &self.framebuffer;
        for row in 0..h {
            let src = (offset + row * stride * 4) as usize;
            let dst = (((y + row) * self.stride as u64 + x) * 4) as usize;
            let bytes = (w * 4) as usize;
            if src.is_multiple_of(8) && dst.is_multiple_of(8) {
                for i in (0..bytes & !7).step_by(8) {
                    to.write64(dst + i, from.read64(src + i));
                }
                if !bytes.is_multiple_of(8) {
                    to.write32(dst + bytes - 4, from.read32(src + bytes - 4));
                }
            } else {
                for i in (0..bytes).step_by(4) {
                    to.write32(dst + i, from.read32(src + i));
                }
            }
        }
        Ok(PresentReply {})
    }
}

fn main(info: &ProcessInfo) -> i64 {
    match run(info) {
        Ok(never) => match never {},
        Err(e) => {
            println!("ERROR: fbdisplay: {e:?}");
            1
        }
    }
}

fn run(info: &ProcessInfo) -> Result<core::convert::Infallible, DeviceError> {
    let device = Device::take(info)?;
    let (size, layout, bar) = (info.args[5], info.args[6], info.args[7] as usize);
    let (width, height, stride) = (size as u32, (size >> 32) as u32, layout as u32);
    let format = match layout >> 32 {
        1 => Format::Rgbx,
        2 => Format::Bgrx,
        _ => return Err(DeviceError::Missing("a framebuffer the firmware set up, in a format this driver knows")),
    };
    if width == 0 || height == 0 || stride < width {
        return Err(DeviceError::Protocol("the framebuffer's description makes no sense"));
    }
    let framebuffer = device.bar(bar).ok_or(DeviceError::Missing("the BAR holding the framebuffer"))?;
    if (framebuffer.len() as u64) < stride as u64 * height as u64 * 4 {
        return Err(DeviceError::Protocol("the framebuffer does not fit its BAR"));
    }
    println!("fbdisplay: {width}x{height}, {stride} pixels a row");
    let mut display = Display { mode: Mode { width, height, format }, stride, framebuffer, attached: None };
    serve(granted(grant::SERVICE), |_badge, request, caps: CapList<Handle>, reply, reply_caps| {
        device::dispatch(&mut display, request, caps, reply, reply_caps)
    })
}
