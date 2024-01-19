#pragma once
#include <stddef.h>

/// Blob is an opaque type that stores a buffer of bytes and their length.
/// It must be created with blob_new() and freed with blob_free().
typedef struct Blob Blob;

/// Allocate a new blob with the given capacity (in bytes) for data.
/// The blob's data will automatically be zeroed out.
/// If malloc() fails, this will return NULL.
Blob* blob_new(size_t size);

/// Get the size of the blob's data. If blob is NULL, returns zero.
size_t blob_get_size(const Blob* blob);

/// Get the data pointer for the blob - non-const. If blob is NULL, returns NULL.
void* blob_get_data_mutable(Blob* blob);

/// Get the data pointer for the blob - const. If blob is NULL, returns NULL.
const void* blob_get_data_const(const Blob* blob);

/// Get the data pointer for the blob. If blob is NULL, returns NULL.
#define blob_get_data(blob) _Generic((blob), const Blob*: blob_get_data_const, Blob*: blob_get_data_mutable)(blob)

/// Free the blob (and its data). If blob is NULL, does nothing.
void blob_free(Blob* blob);
