#ifndef TCHEADERUNPACK_H
#define TCHEADERUNPACK_H

#include <stdint.h>
#include <stddef.h>

struct SecondaryHeader {
    unsigned int ackFlags : 4;
    unsigned int serviceTypeID : 8;
    unsigned int messageSubtypeID : 8;
    unsigned int messageCounter : 16;
    unsigned int spare : 4;   
};

int unpack_packet(
    const uint8_t *packet,
    size_t packet_len,
    size_t hmac_len,
    uint8_t **packet_without_hmac,
    size_t *packet_without_hmac_len,
    uint8_t **hmac
);

/*
 * Reset the active HMAC key to the demo default or set it to a specific
 * runtime value before verification begins.
 * Returns 0 on success and -1 on invalid input or allocation failure.
 */
int reset_active_hmac_key(void);
int set_active_hmac_key(const uint8_t *key, size_t key_len);

/*
 * Recompute HMAC-SHA256 over packet_without_hmac using the current active key,
 * then compare against the provided HMAC.
 * Returns 1 on match, 0 on mismatch, and -1 on invalid input.
 */
int verify_packet_hmac(const uint8_t *packet_without_hmac,
                       size_t packet_without_hmac_len,
                       const uint8_t *hmac,
                       size_t hmac_len);

#endif