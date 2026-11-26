//! TCP's wire format over IPv4 (RFC 9293): the segment header and the
//! options this stack uses (MSS, window scale and timestamps from RFC 7323,
//! SACK from RFC 2018). The connection's behaviour is [`crate::tcp_conn`].
//!
//! A segment is built in two steps so that its payload is written once,
//! straight from wherever it lies: [`header`] writes the header and its
//! options at the front of a buffer, the caller puts the payload after it,
//! and [`seal`] puts the checksum in over both.

use crate::checksum::Sum;
use crate::{Ipv4, Malformed, be16, be32};

/// The header without options.
pub const HEADER: usize = 20;
/// The longest header: 15 words.
pub const MAX_HEADER: usize = 60;

/// The flags this stack reads and writes.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Most SACK blocks one segment carries: four fill the option space alone,
/// three when timestamps are there too.
pub const SACK_BLOCKS: usize = 4;

/// The options a segment carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// The largest segment the sender takes (SYN only).
    pub mss: Option<u16>,
    /// The sender's window scale shift, at most 14 (SYN only).
    pub window_scale: Option<u8>,
    /// The sender understands SACK blocks (SYN only).
    pub sack_permitted: bool,
    /// The sender's timestamp and the one it echoes.
    pub timestamps: Option<(u32, u32)>,
    /// Ranges `[start, end)` of sequence numbers the sender holds beyond
    /// its acknowledgement; the first `sack_len` are used.
    pub sack: [(u32, u32); SACK_BLOCKS],
    pub sack_len: u8,
}

impl Options {
    /// The bytes these options take on the wire, padded to a word.
    pub fn len(&self) -> usize {
        let mut n = 0;
        if self.mss.is_some() {
            n += 4;
        }
        if self.window_scale.is_some() {
            n += 4; // NOP and the three-byte option
        }
        if self.sack_permitted {
            n += 4; // two NOPs and the two-byte option, or with timestamps
        }
        if self.timestamps.is_some() {
            n += 12; // two NOPs and the ten-byte option
        }
        if self.sack_len > 0 {
            n += 4 + 8 * self.sack_len as usize; // two NOPs, kind, length
        }
        n
    }

    /// Whether there are no options.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A segment's header fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// A segment: its header, options and data.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    pub header: Header,
    pub options: Options,
    pub data: &'a [u8],
}

impl Segment<'_> {
    /// Whether the flag (or every flag) in `f` is set.
    pub fn has(&self, f: u8) -> bool {
        self.header.flags & f == f
    }

    /// The sequence space it takes: its data, and one each for SYN and FIN.
    pub fn len(&self) -> u32 {
        self.data.len() as u32 + self.has(SYN) as u32 + self.has(FIN) as u32
    }

    /// Whether it takes no sequence space.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Read a segment (an IPv4 payload) sent from `src` to `dst`. The
/// checksum is required; options are checked for their lengths, and those
/// this stack does not use are skipped.
pub fn parse(p: &[u8], src: Ipv4, dst: Ipv4) -> Result<Segment<'_>, Malformed> {
    if p.len() < HEADER {
        return Err(Malformed::Truncated);
    }
    let offset = (p[12] >> 4) as usize * 4;
    if offset < HEADER {
        return Err(Malformed::BadHeader);
    }
    if p.len() < offset {
        return Err(Malformed::Truncated);
    }
    let len = u16::try_from(p.len()).map_err(|_| Malformed::BadHeader)?;
    if Sum::new().pseudo(src, dst, crate::ipv4::TCP, len).bytes(p).finish() != 0 {
        return Err(Malformed::BadChecksum);
    }
    let header = Header { src_port: be16(p, 0), dst_port: be16(p, 2), seq: be32(p, 4), ack: be32(p, 8), flags: p[13], window: be16(p, 14) };
    let options = parse_options(&p[HEADER..offset])?;
    Ok(Segment { header, options, data: &p[offset..] })
}

fn parse_options(mut o: &[u8]) -> Result<Options, Malformed> {
    let mut out = Options::default();
    while let [kind, rest @ ..] = o {
        match kind {
            0 => break,
            1 => {
                o = rest;
                continue;
            }
            _ => {}
        }
        let [len, ..] = rest else { return Err(Malformed::BadOptions) };
        let len = *len as usize;
        if len < 2 || len > o.len() {
            return Err(Malformed::BadOptions);
        }
        let body = &o[2..len];
        match (kind, body.len()) {
            (2, 2) => out.mss = Some(be16(body, 0)),
            (3, 1) => out.window_scale = Some(body[0].min(14)),
            (4, 0) => out.sack_permitted = true,
            (8, 8) => out.timestamps = Some((be32(body, 0), be32(body, 4))),
            (5, n) if n % 8 == 0 && n > 0 => {
                for (i, b) in body.as_chunks::<8>().0.iter().take(SACK_BLOCKS).enumerate() {
                    out.sack[i] = (be32(b, 0), be32(b, 4));
                    out.sack_len = i as u8 + 1;
                }
            }
            // A known option of the wrong length is not skipped: the
            // sender means something this stack cannot read.
            (2..=5 | 8, _) => return Err(Malformed::BadOptions),
            _ => {}
        }
        o = &o[len..];
    }
    Ok(out)
}

/// Write the header of a segment with `options` at the front of `out` and
/// return its length; the payload goes right after it, then [`seal`].
pub fn header(out: &mut [u8], h: &Header, options: &Options) -> Option<usize> {
    let len = HEADER + options.len();
    if len > MAX_HEADER {
        return None;
    }
    let d = out.get_mut(..len)?;
    d[0..2].copy_from_slice(&h.src_port.to_be_bytes());
    d[2..4].copy_from_slice(&h.dst_port.to_be_bytes());
    d[4..8].copy_from_slice(&h.seq.to_be_bytes());
    d[8..12].copy_from_slice(&h.ack.to_be_bytes());
    d[12] = ((len / 4) as u8) << 4;
    d[13] = h.flags;
    d[14..16].copy_from_slice(&h.window.to_be_bytes());
    d[16..20].fill(0);
    let mut at = HEADER;
    let mut put = |bytes: &[u8]| {
        d[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    if let Some(mss) = options.mss {
        put(&[2, 4]);
        put(&mss.to_be_bytes());
    }
    if let Some(s) = options.window_scale {
        put(&[1, 3, 3, s]);
    }
    if options.sack_permitted {
        put(&[1, 1, 4, 2]);
    }
    if let Some((val, ecr)) = options.timestamps {
        put(&[1, 1, 8, 10]);
        put(&val.to_be_bytes());
        put(&ecr.to_be_bytes());
    }
    if options.sack_len > 0 {
        put(&[1, 1, 5, 2 + 8 * options.sack_len]);
        for &(s, e) in &options.sack[..options.sack_len as usize] {
            put(&s.to_be_bytes());
            put(&e.to_be_bytes());
        }
    }
    Some(len)
}

/// Put the checksum into the segment `seg` (header and payload) sent from
/// `src` to `dst`.
pub fn seal(seg: &mut [u8], src: Ipv4, dst: Ipv4) {
    seg[16..18].fill(0);
    let sum = Sum::new().pseudo(src, dst, crate::ipv4::TCP, seg.len() as u16).bytes(seg).finish();
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
}

/// For an interface that sums the checksum (`silica.net.Device`'s checksum
/// offload): only the pseudo-header's folded sum goes in the field, not
/// complemented, as the device adds the segment's bytes and complements.
/// `len` is the whole segment's TCP length, also when the device cuts it.
pub fn seal_partial(seg: &mut [u8], src: Ipv4, dst: Ipv4) {
    let sum = !Sum::new().pseudo(src, dst, crate::ipv4::TCP, seg.len() as u16).finish();
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
}

/// Write a whole segment carrying `data`; returns its length.
pub fn build(out: &mut [u8], src: Ipv4, dst: Ipv4, h: &Header, options: &Options, data: &[u8]) -> Option<usize> {
    let n = header(out, h, options)?;
    let end = n.checked_add(data.len()).filter(|&e| e <= u16::MAX as usize)?;
    out.get_mut(n..end)?.copy_from_slice(data);
    seal(&mut out[..end], src, dst);
    Some(end)
}

/// A question to the peer of a connection this stack no longer holds (the
/// last stack's, kept as how far each side had sent): a bare ACK a
/// quarter of the sequence space behind what was sent, which no window
/// takes, so a peer that still holds the connection answers it with an
/// ACK naming exactly the next byte it expects (RFC 9293 3.10.7.4), and
/// one that does not, with a reset. That answer reaches no connection
/// here, and [`reset_reply`] to it is the reset the peer takes: its own
/// number, not the one the last stack wrote down, which may be behind
/// what it sent or at the edge of the peer's window (where a reset is
/// dropped without a word, RFC 5961).
pub fn reset_probe(local_port: u16, remote_port: u16, sent_to: u32, received_to: u32) -> Header {
    Header { src_port: local_port, dst_port: remote_port, seq: sent_to.wrapping_sub(1 << 30), ack: received_to, flags: ACK, window: 0 }
}

/// What answers a segment that reaches no connection (RFC 9293 3.10.7.1):
/// a reset that the sender will take as meant for it, or nothing to a
/// reset.
pub fn reset_reply(s: &Segment<'_>) -> Option<Header> {
    if s.has(RST) {
        return None;
    }
    let h = &s.header;
    let (seq, ack, flags) = if s.has(ACK) { (h.ack, 0, RST) } else { (0, h.seq.wrapping_add(s.len()), RST | ACK) };
    Some(Header { src_port: h.dst_port, dst_port: h.src_port, seq, ack, flags, window: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4 = Ipv4([10, 0, 2, 15]);
    const B: Ipv4 = Ipv4([10, 0, 2, 2]);

    fn every_option() -> Options {
        let mut o = Options {
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamps: Some((0xDEAD_BEEF, 7)),
            ..Options::default()
        };
        o.sack[0] = (100, 200);
        o.sack_len = 1;
        o
    }

    #[test]
    fn segments_round_trip_with_every_option() {
        let h = Header { src_port: 80, dst_port: 50000, seq: 0xFFFF_FFF0, ack: 12, flags: SYN | ACK, window: 65535 };
        let o = every_option();
        let mut b = [0u8; 128];
        let n = build(&mut b, A, B, &h, &o, b"hello").unwrap();
        assert_eq!(n, HEADER + o.len() + 5);
        assert_eq!((HEADER + o.len()) % 4, 0, "the header is whole words");
        let s = parse(&b[..n], A, B).unwrap();
        assert_eq!(s.header, h);
        assert_eq!(s.options, o);
        assert_eq!(s.data, b"hello");
        assert_eq!(s.len(), 6, "SYN takes one, FIN none here, and the data five");
        assert_eq!(parse(&b[..n], A, Ipv4([1, 2, 3, 4])).unwrap_err(), Malformed::BadChecksum);
    }

    #[test]
    fn malformed_segments_are_refused_and_unknown_options_skipped() {
        let h = Header { src_port: 1, dst_port: 2, ..Header::default() };
        let mut b = [0u8; 64];
        let n = build(&mut b, A, B, &h, &Options::default(), &[]).unwrap();
        assert_eq!(parse(&b[..n - 1], A, B).unwrap_err(), Malformed::Truncated);
        let reseal = |b: &mut [u8], n: usize| seal(&mut b[..n], A, B);
        let mut c = b;
        c[12] = 4 << 4;
        reseal(&mut c, n);
        assert_eq!(parse(&c[..n], A, B).unwrap_err(), Malformed::BadHeader, "an offset under 20");
        let mut c = b;
        c[12] = 6 << 4;
        reseal(&mut c, n);
        assert_eq!(parse(&c[..n], A, B).unwrap_err(), Malformed::Truncated, "an offset past the end");
        // Options: an unknown one is skipped, a bad length refused.
        let with = |opts: &[u8]| {
            let mut c = [0u8; 64];
            c[..HEADER].copy_from_slice(&b[..HEADER]);
            c[12] = (((HEADER + opts.len()) / 4) as u8) << 4;
            c[HEADER..HEADER + opts.len()].copy_from_slice(opts);
            let n = HEADER + opts.len();
            seal(&mut c[..n], A, B);
            parse(&c[..n], A, B).map(|s| s.options)
        };
        assert_eq!(with(&[30, 4, 9, 9, 2, 4, 5, 180]).unwrap().mss, Some(1460), "kind 30 skipped");
        assert_eq!(with(&[2, 3, 5, 0]).unwrap_err(), Malformed::BadOptions, "an MSS of three bytes");
        assert_eq!(with(&[30, 9, 0, 0]).unwrap_err(), Malformed::BadOptions, "a length past the end");
        assert_eq!(with(&[30, 1, 0, 0]).unwrap_err(), Malformed::BadOptions, "a length under two");
        assert_eq!(with(&[1, 1, 1, 2]).unwrap_err(), Malformed::BadOptions, "a kind without its length");
        assert_eq!(with(&[0, 2, 4, 9]).unwrap(), Options::default(), "nothing after the end of the list");
        assert_eq!(with(&[3, 3, 20, 0]).unwrap().window_scale, Some(14), "a shift over 14 is taken as 14");
    }

    #[test]
    fn the_options_fit_and_a_header_too_long_is_not_built() {
        let mut o = every_option();
        o.mss = None;
        o.window_scale = None;
        o.sack_permitted = false;
        o.sack_len = 3;
        assert!(o.len() <= MAX_HEADER - HEADER, "timestamps and three SACK blocks fit");
        o.sack_len = 4;
        let mut b = [0u8; 128];
        assert!(header(&mut b, &Header::default(), &o).is_none(), "timestamps and four SACK blocks do not");
        o.timestamps = None;
        assert!(header(&mut b, &Header::default(), &o).is_some(), "four SACK blocks alone do");
    }

    #[test]
    fn a_stray_segment_is_answered_with_a_reset_it_accepts() {
        let syn = Segment {
            header: Header { src_port: 4000, dst_port: 80, seq: 100, flags: SYN, ..Header::default() },
            options: Options::default(),
            data: b"",
        };
        let r = reset_reply(&syn).unwrap();
        assert_eq!((r.seq, r.ack, r.flags, r.src_port, r.dst_port), (0, 101, RST | ACK, 80, 4000));
        let ack = Segment { header: Header { ack: 555, flags: ACK, ..syn.header }, ..syn };
        let r = reset_reply(&ack).unwrap();
        assert_eq!((r.seq, r.flags), (555, RST));
        let rst = Segment { header: Header { flags: RST, ..syn.header }, ..syn };
        assert!(reset_reply(&rst).is_none(), "a reset is never answered");
    }
}
