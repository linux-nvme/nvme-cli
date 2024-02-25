#ifndef crc32_H
#define crc32_H

#include <stdint.h>
#include <stddef.h>

uint32_t crc32(uint32_t crc, const void *buf, size_t len);

#endif
