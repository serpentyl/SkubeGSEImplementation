#ifndef TCHEADERPACK_H
#define TCHEADERPACK_H

#include <stddef.h>
#include <stdint.h>

/*
 * Build a TC secondary-header packet: 5-byte packed header + message + HMAC-SHA256.
 * Returns a malloc'd buffer (caller must free). Writes total length to *out_len.
 * If hmac_out is non-NULL it receives a copy of the 32-byte HMAC.
 */
uint8_t *build_tc_packet(const char *key, const char *message,
                         uint16_t counter, size_t *out_len,
                         uint8_t *hmac_out);

#endif