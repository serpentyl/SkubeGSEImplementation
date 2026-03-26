#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "TCHeaderUnpack.h"
#include "hmac_sha256/hmac_sha256.h"
#include "hmac_sha256/sha256.h"

#define DEFAULT_TC_HMAC_KEY "SkubeTradeshowDemoKey"

static uint8_t *active_hmac_key = NULL;
static size_t active_hmac_key_len = 0;

static int update_active_hmac_key_internal(const uint8_t *key, size_t key_len)
{
    uint8_t *new_key;

    if(key == NULL || key_len == 0)
        return -1;

    new_key = (uint8_t *)malloc(key_len);
    if(new_key == NULL)
        return -1;

    memcpy(new_key, key, key_len);
    free(active_hmac_key);
    active_hmac_key = new_key;
    active_hmac_key_len = key_len;
    return 0;
}

int reset_active_hmac_key(void)
{
    return update_active_hmac_key_internal((const uint8_t *)DEFAULT_TC_HMAC_KEY,
                                           strlen(DEFAULT_TC_HMAC_KEY));
}

int set_active_hmac_key(const uint8_t *key, size_t key_len)
{
    return update_active_hmac_key_internal(key, key_len);
}

int unpack_packet(
    const uint8_t *packet,
    size_t packet_len,
    size_t hmac_len,
    uint8_t **packet_without_hmac,
    size_t *packet_without_hmac_len,
    uint8_t **hmac
) {
    size_t base_packet_len;

    if (packet == NULL || packet_without_hmac == NULL || packet_without_hmac_len == NULL || hmac == NULL) {
        return -1;
    }

    if (packet_len < hmac_len) {
        return -1;
    }

    base_packet_len = packet_len - hmac_len;
    *packet_without_hmac_len = base_packet_len;

    *packet_without_hmac = (uint8_t *)malloc(base_packet_len);
    if (*packet_without_hmac == NULL) {
        return -1;
    }

    *hmac = (uint8_t *)malloc(hmac_len);
    if (*hmac == NULL) {
        free(*packet_without_hmac);
        *packet_without_hmac = NULL;
        return -1;
    }

    memcpy(*packet_without_hmac, packet, base_packet_len);
    memcpy(*hmac, packet + base_packet_len, hmac_len);

    return 0;
}

int verify_packet_hmac(const uint8_t *packet_without_hmac,
                       size_t packet_without_hmac_len,
                       const uint8_t *hmac,
                       size_t hmac_len)
{
    uint8_t computed_hmac[SHA256_HASH_SIZE];

    if(packet_without_hmac == NULL || hmac == NULL)
    {
        return -1;
    }

    if(hmac_len != SHA256_HASH_SIZE || active_hmac_key == NULL || active_hmac_key_len == 0)
    {
        return -1;
    }

    hmac_sha256(active_hmac_key,
                active_hmac_key_len,
                packet_without_hmac,
                packet_without_hmac_len,
                computed_hmac,
                sizeof(computed_hmac));

    return (memcmp(computed_hmac, hmac, SHA256_HASH_SIZE) == 0) ? 1 : 0;
}
