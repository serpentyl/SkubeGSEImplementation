//This can be deleted

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "TCHeaderUnpack.h"
#include "TCHeaderPack.h"
#include "hmac_sha256/hmac_sha256.h"
#include "hmac_sha256/sha256.h"

int main(void) {
    const char* str_key = "SkubeTradeshowDemoKey";      // HMAC key (should be kept secret in real applications)
    uint8_t out[SHA256_HASH_SIZE];                      // Buffer to hold the HMAC output
    uint8_t unpacked_out[SHA256_HASH_SIZE];             // Buffer to hold the HMAC output from unpacked packet
    uint8_t *unpacked_hmac = NULL;                      // Buffer to hold the unpacked HMAC
    uint8_t *unpacked_packet = NULL;                    // Buffer to hold the unpacked packet (header + message)
    const char *message = "Testing Message";            // Message to be included in the packet
    size_t packet_len = 0;
    size_t unpacked_packet_len = 0;

    // Build the TC secondary-header packet (header + message + HMAC)
    uint8_t *packet = build_tc_packet(str_key, message, &packet_len, out);
    if (packet == NULL) {
        return 1;
    }

    // Print the packet and HMAC in hex format for verification
    printf("Packet + HMAC hex: ");
    for (size_t i = 0; i < packet_len; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    // Print the key of HMAC in hex format for verification
    printf("Key hex: ");
    for (size_t i = 0; i < strlen(str_key); i++) {
        printf("%02x ", (uint8_t)str_key[i]);
    }
    printf("\n");

    // Print the HMAC in hex format for verification
    printf("HMAC hex: ");
    for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x ", out[i]);
    }
    printf("\n");

    // Simulate receiving the packet and unpacking it
    if (unpack_packet(
        packet,
        packet_len,
        SHA256_HASH_SIZE,
        &unpacked_packet,
        &unpacked_packet_len,
        &unpacked_hmac
    ) == 0) {
        printf("Unpacked packet (Header + Message) hex: ");
        for (size_t i = 0; i < unpacked_packet_len; i++) {
            printf("%02x ", unpacked_packet[i]);
        }
        printf("\n");

        printf("Unpacked HMAC hex: ");
        for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
            printf("%02x ", unpacked_hmac[i]);
        }
        printf("\n");

        //Simulate verifying the HMAC of the unpacked packet
        hmac_sha256(str_key, strlen(str_key), unpacked_packet, unpacked_packet_len, unpacked_out, sizeof(unpacked_out));

        if (memcmp(out, unpacked_out, SHA256_HASH_SIZE) == 0) {
            printf("out and unpacked_out match: true\n");
        } else {
            printf("out and unpacked_out match: false\n");
        }
    }

    //Free allocated memory
    free(unpacked_hmac);
    free(unpacked_packet);
    free(packet);

    return 0;
}