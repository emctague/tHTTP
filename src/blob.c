#include "blob.h"
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>

struct Blob {
    size_t length;
    uint8_t data[];
};

Blob* blob_new(const size_t size)
{
    Blob* blob = malloc(sizeof(Blob) + size);
    if (!blob) return NULL;

    blob->length = size;

    bzero(blob_get_data(blob), size);

    return blob;
}

size_t blob_get_size(const Blob* blob)
{
    if (blob != NULL) return blob->length;
    return 0;
}

void* blob_get_data_mutable(Blob* blob)
{
    if (blob != NULL) return blob->data;
    return blob;
}

const void* blob_get_data_const(const Blob* blob)
{
    if (blob != NULL) return blob->data;
    return blob;
}


void blob_free(Blob* blob)
{
    if (blob != NULL) free(blob);
}

