#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

/// An opaque container for a parsed PE file (either PE32 or PE32+)
struct PeFile;

using RichEntryCallback = bool(*)(uint32_t, uint32_t, void*);

extern "C" {

/// Create a new `PeFile`.
///
/// Returns `null` on all errors.
///
/// # Safety
///
/// * `data` must be no less than `len` bytes long
/// * `data` must outlive the returned `PeFile`
PeFile *pe_new_from_parts(const unsigned char *data, size_t len);

/// Destroy the given `PeFile`.
///
/// This does *not* destroy the backing data.
///
/// # Safety
///
/// * `pe` must point to a valid `PeFile`
void pe_destroy(PeFile *pe);

/// Returns a **borrowed** pointer to an `ImageDosHeader` representing this PE file's DOS
/// header.
///
/// # Safety
///
/// * `pe` must point to a valid `PeFile`
/// * The returned pointer must not outlive `pe`
const ImageDosHeader *pe_get_dos_header(const PeFile *pe);

/// Returns a **borrowed** pointer to an `ImageFileHeader` representing this PE file's COFF
/// header.
///
/// # Safety
///
/// * `pe` must point to a valid `PeFile`
/// * The returned pointer must not outlive `pe`
const ImageFileHeader *pe_get_coff_header(const PeFile *pe);

/// Returns whether or not this `PeFile` contains a Rich header.
///
/// # Safety
///
/// * `pe` must point to a valid `PeFile`
bool pe_has_rich_header(const PeFile *pe);

/// Yield each entry in the given `PeFile`'s Rich header to a callback.
/// Callbacks have the following signature:
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
/// If the given `PeFile` has no Rich header, the callback is not invoked.
///
/// # Safety
///
/// * `pe` must point to a valid `PeFile`
void pe_iter_rich_header(const PeFile *pe, RichEntryCallback callback, void *userdata);

} // extern "C"
