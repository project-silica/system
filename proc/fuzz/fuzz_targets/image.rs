//! Any bytes as a program sent to the service manager (`update`): the
//! loader's checks (`silica_proc::check_image`) never panic, and what they
//! accept is what `spawn` may load: at least one segment, each in whole
//! pages below the start-up record, no two sharing a page.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|image: &[u8]| {
    let Ok(pages) = silica_proc::check_image(image) else { return };
    assert!(!pages.is_empty() && pages.len() <= silica_proc::MAX_SEGMENTS);
    for (i, &(start, end)) in pages.iter().enumerate() {
        assert!(start <= end && end <= silica_proc::INFO_VADDR as u64, "a segment outside the program's addresses");
        assert!(start % 4096 == 0 && end % 4096 == 0, "a segment not in whole pages");
        for &(s, e) in &pages[..i] {
            assert!(start == end || s == e || end <= s || e <= start, "two segments share a page");
        }
    }
});
