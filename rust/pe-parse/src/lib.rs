#![forbid(clippy::expect_used)]
#![forbid(clippy::unwrap_used)]
#![forbid(clippy::panic)]

use std::slice;

use libc::{c_uchar, c_void, size_t};
use object::read::pe;
use object::FileKind;

/// An opaque container for a parsed PE file (either PE32 or PE32+)
pub enum PeFile<'data> {
    Pe32(pe::PeFile32<'data>),
    Pe64(pe::PeFile64<'data>),
}

impl PeFile<'_> {
    fn rich_header_info(&self) -> Option<pe::RichHeaderInfo<'_>> {
        match self {
            PeFile::Pe32(pe) => pe.rich_header_info(),
            PeFile::Pe64(pe) => pe.rich_header_info(),
        }
    }
}

/// Create a new `PeFile`.
///
/// Returns `null` on all errors.
///
/// # Safety
///
/// * `data` must be no less than `len` bytes long
/// * `data` must outlive the returned `PeFile`
#[no_mangle]
pub unsafe extern "C" fn pe_new_from_parts<'data>(
    data: *const c_uchar,
    len: size_t,
) -> *mut PeFile<'data> {
    let data = slice::from_raw_parts(data, len);

    // Sniff the kind of PE we're parsing.
    let kind = match FileKind::parse(data) {
        Ok(kind) => kind,
        Err(_) => return std::ptr::null_mut(),
    };

    let pe_file = match kind {
        FileKind::Pe32 => match pe::PeFile32::parse(data) {
            Ok(pe) => PeFile::Pe32(pe),
            Err(_) => return std::ptr::null_mut(),
        },
        FileKind::Pe64 => match pe::PeFile64::parse(data) {
            Ok(pe) => PeFile::Pe64(pe),
            Err(_) => return std::ptr::null_mut(),
        },
        _ => return std::ptr::null_mut(),
    };

    Box::into_raw(Box::new(pe_file))
}

/// Destroy the given `PeFile`.
///
/// This does *not* destroy the backing data.
///
/// # Safety
///
/// * `pe` must point to a valid `PeFile`
#[no_mangle]
pub unsafe extern "C" fn pe_destroy<'data>(pe: *mut PeFile<'data>) {
    drop(Box::from_raw(pe))
}

/// An opaque container for a Rich header.
pub struct RichHeader<'data>(pe::RichHeaderInfo<'data>);

/// Retrieve the Rich header from the given `PeFile`, if present.
///
/// Returns `null` if the file doesn't contain a Rich header.
///
/// Must be freed using `pe_destroy_rich_header`.
///
/// # Safety
///
/// * `pe` must be a valid `PeFile`
/// * `pe` must outlive the returned `RichHeader`
#[no_mangle]
pub unsafe extern "C" fn pe_get_rich_header<'data>(
    pe: *const PeFile<'data>,
) -> *mut RichHeader<'data> {
    let pe = &*pe;

    match pe.rich_header_info() {
        Some(rich) => Box::into_raw(Box::new(RichHeader(rich))),
        None => std::ptr::null_mut(),
    }
}

/// Destroy the given `RichHeader`.
///
/// # Safety
///
/// * `rich` must point to a valid `RichHeader`
#[no_mangle]
pub unsafe extern "C" fn pe_destroy_rich_header<'data>(rich: *mut RichHeader<'data>) {
    drop(Box::from_raw(rich))
}

type RichEntryCallback = unsafe extern "C" fn(u32, u32, *mut c_void) -> bool;

/// Yield each entry in the given `RichHeader` to a callback. Callbacks have
/// the following signature:
///
/// ```c
/// bool handle_rich_entry(uint32_t comp_id, uint32_t count, void* userdata);
/// ```
///
/// Where `comp_id` is the entry's component ID, `count` is the entry's count,
/// and `userdata` optional, user-supplied callback state.
///
/// Callbacks can return `true` to continue the surrounding iteration,
/// or `false` to terminate it.
///
/// # Safety
///
/// * `rich` must point to a valid `RichHeader`
#[no_mangle]
pub unsafe extern "C" fn pe_iter_rich_header<'data>(
    rich: *const RichHeader<'data>,
    callback: RichEntryCallback,
    userdata: *mut c_void,
) {
    let rich = &*rich;

    for entry in rich.0.unmasked_entries() {
        if !callback(entry.comp_id, entry.count, userdata) {
            break;
        }
    }
}
