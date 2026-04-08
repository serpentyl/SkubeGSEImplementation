#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "TCHeaderPack.h"
#include "TCHeaderUnpack.h"
#include "hmac_sha256/hmac_sha256.h"
#include "hmac_sha256/sha256.h"

/* Internal helper: appends suffix to a realloc'd buffer. Frees buffer on failure. */
static uint8_t *append_bytes_internal(uint8_t *buffer, size_t *buffer_len,
                                      const uint8_t *suffix, size_t suffix_len)
{
    uint8_t *resized = (uint8_t *)realloc(buffer, *buffer_len + suffix_len);
    if(resized == NULL) { free(buffer); return NULL; }
    memcpy(resized + *buffer_len, suffix, suffix_len);
    *buffer_len += suffix_len;
    return resized;
}

uint8_t *build_tc_packet(const char *key, const char *message,
                         uint16_t counter, size_t *out_len,
                         uint8_t *hmac_out)
{
    const char *ack_env;
    const char *rotate_env;
    char *end_ptr;
    unsigned long parsed_ack;
    size_t message_len = strlen(message);
    size_t packet_len  = 5 + message_len;
    uint8_t hmac[SHA256_HASH_SIZE];

    uint8_t *packet = (uint8_t *)malloc(packet_len);
    if(packet == NULL) return NULL;

    struct SecondaryHeader hdr = {0};
    hdr.ackFlags        = 0;
    hdr.serviceTypeID    = 1;
    hdr.messageSubtypeID = 1;
    hdr.messageCounter   = counter;

    if(strstr(message, "Light") != NULL || strstr(message, "LED") != NULL)
    {
        hdr.serviceTypeID = 2;
        hdr.messageSubtypeID = 2;
    }

    rotate_env = getenv("TC_ROTATE_HMAC_KEY");
    if(rotate_env != NULL && rotate_env[0] != '\0' && rotate_env[0] != '0')
        hdr.messageSubtypeID = 3;

    ack_env = getenv("TC_ACK_FLAGS");
    if(ack_env != NULL && ack_env[0] != '\0')
    {
        errno = 0;
        parsed_ack = strtoul(ack_env, &end_ptr, 10);
        if(errno == 0 && end_ptr != ack_env && *end_ptr == '\0' && parsed_ack <= 0x0Fu)
            hdr.ackFlags = (unsigned int)parsed_ack;
    }

    uint8_t raw_hdr[5] = {0};
    raw_hdr[0] = (uint8_t)(((hdr.ackFlags        & 0xF) << 4) | (hdr.serviceTypeID    >> 4));
    raw_hdr[1] = (uint8_t)(((hdr.serviceTypeID    & 0xF) << 4) | (hdr.messageSubtypeID >> 4));
    raw_hdr[2] = (uint8_t)(((hdr.messageSubtypeID & 0xF) << 4) | (hdr.messageCounter   >> 12));
    raw_hdr[3] = (uint8_t)((hdr.messageCounter >> 4) & 0xFF);
    raw_hdr[4] = (uint8_t)(((hdr.messageCounter & 0xF) << 4) | (hdr.spare & 0xF));

    memcpy(packet, raw_hdr, 5);
    memcpy(packet + 5, message, message_len);

    hmac_sha256(key, strlen(key), packet, packet_len, hmac, sizeof(hmac));
    if(hmac_out != NULL)
        memcpy(hmac_out, hmac, SHA256_HASH_SIZE);

    packet = append_bytes_internal(packet, &packet_len, hmac, sizeof(hmac));
    if(packet == NULL) return NULL;

    *out_len = packet_len;
    return packet;
}