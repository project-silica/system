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

use silica_driver::{Device, DeviceError, framebuffer, grant, granted};
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
    attached: Option<(Handle, mem::Lent)>,
    /// The badge of the client that attached it (the device manager gives
    /// each holder it opens the driver for a badge of its own), and of the
    /// call being answered: only the attacher presents.
    attacher: u64,
    caller: u64,
}

impl device::Server<Handle> for Display {
    fn mode(&mut self) -> ModeReply {
        ModeReply { mode: self.mode.clone() }
    }

    fn attach(&mut self, pixels: Handle) -> Result<AttachReply, Error> {
        // One client draws: another may attach only once the last frame
        // has gone (its client took it back, or ended, and the capability
        // with it).
        if self.attached.as_ref().is_some_and(|(f, _)| matches!(sys::inspect_slot(slots::SPACE, f.cap().0), Ok(Some(_)))) {
            return Err(Error::InUse);
        }
        self.attached = None;
        let bits = match sys::inspect_slot(slots::SPACE, pixels.cap().0) {
            Ok(Some(s)) if s.ty == sys::ObjectType::Frame => s.bits,
            _ => return Err(Error::BadMemory),
        };
        // Among lent memory: taking it back leaves zeros, never a fault.
        let region = mem::Lent::map(pixels.cap(), bits, Rights::READ).map_err(|_| Error::BadMemory)?;
        self.attached = Some((pixels, region));
        self.attacher = self.caller;
        Ok(AttachReply {})
    }

    fn present(&mut self, rect: Rect, offset: u64, stride: u32) -> Result<PresentReply, Error> {
        // Only the client that attached the frame presents it: any other
        // holder of the driver chose when, and which parts of, the
        // attacher's frame reached the screen (the audit of 2026-11-27).
        let Some((_, lent)) = self.attached.as_ref().filter(|_| self.caller == self.attacher) else { return Err(Error::NotAttached) };
        let from = lent.region();
        let Rect { x, y, width, height } = rect;
        let (x, y, w, h) = (x as u64, y as u64, width as u64, height as u64);
        if w == 0 || h == 0 {
            return Ok(PresentReply {});
        }
        let on_screen = x + w <= self.mode.width as u64 && y + h <= self.mode.height as u64;
        // Every byte of the rectangle, row padding included, in the frame:
        // checked arithmetic, as a maximum-size rectangle overflowed it.
        let last = framebuffer::byte_end(offset, width, height, stride);
        if !on_screen || last.is_none_or(|l| l > from.len() as u64) {
            return Err(Error::Outside);
        }
        let to = &self.framebuffer;
        for row in 0..h {
            let src = (offset + row * u64::from(stride) * 4) as usize;
            let dst = (((y + row) * self.stride as u64 + x) * 4) as usize;
            // Pixels may start at any byte: a client's offset is its own.
            framebuffer::copy_row(to, dst, &from, src, width);
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
    if framebuffer::byte_end(0, stride, height, stride).is_none_or(|end| end > framebuffer.len() as u64) {
        return Err(DeviceError::Protocol("the framebuffer does not fit its BAR"));
    }
    println!("fbdisplay: {width}x{height}, {stride} pixels a row");
    let mut display = Display { mode: Mode { width, height, format }, stride, framebuffer, attached: None, attacher: 0, caller: 0 };
    serve(granted(grant::SERVICE), |badge, request, caps: CapList<Handle>, reply, reply_caps| {
        display.caller = badge;
        device::dispatch(&mut display, request, caps, reply, reply_caps)
    })
}
