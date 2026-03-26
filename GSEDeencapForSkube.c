/*
 * GSE de-encapsulation — binary file input, raw payload output
 *
 * Reads back-to-back raw GSE packets from a binary file,
 * de-encapsulates them, and writes the recovered payload to an output file.
 *
 * The input file is expected to be in the format produced by GSEEncapForSkube.c:
 * back-to-back raw GSE packets, each self-delimiting via the GSE length field.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* GSE includes */
#include "GSE/libgse/src/common/constants.h"
#include "GSE/libgse/src/deencap/deencap.h"

/* TC unpacking */
#include "TCHeaderUnpack.h"
#include "hmac_sha256/sha256.h"

/* -------------------------------------------------------------------------
 * Configuration — must match the values used in GSEEncapForSkube.c
 * ------------------------------------------------------------------------- */

/** Number of QoS queues — must be >= the QOS value used during encapsulation */
#define QOS_NBR     1

/** Protocol type — must match what was used during encapsulation */
#define PROTOCOL    0x1234

/** Label type used during encapsulation */
#define LABEL_TYPE  0

/** Input binary file (produced by GSEEncapForSkube) */
#define INPUT_FILE  "gse_output.bin"

/** Output file for the recovered payload bytes */
#define OUTPUT_FILE "payload_recovered.bin"

/** Debug printing: set to 1 to enable, 0 to disable */
#define VERBOSE     1

#define DEBUG(verbose, format, ...) \
  do { if(verbose) printf(format, ##__VA_ARGS__); } while(0)

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(void)
{
    gse_deencap_t *deencap    = NULL;
    gse_vfrag_t   *gse_packet = NULL;
    gse_vfrag_t   *pdu        = NULL;
    gse_status_t   status;
    uint8_t        label[6];
    uint8_t        label_type;
    uint16_t       protocol;
    uint16_t       gse_length;
    FILE          *in_file    = NULL;
    FILE          *out_file   = NULL;
    int            is_failure = 1;
    int            pkt_count  = 0;
    int            pdu_count  = 0;
    uint8_t        hdr[2];
    uint16_t       remainder_len;
    unsigned char *raw_pkt    = NULL;
    uint8_t       *tc_payload  = NULL;
    size_t         tc_payload_len = 0;
    uint8_t       *tc_hmac     = NULL;
    const char    *tc_hmac_key_env = NULL;
    int            print_release_msg = 0;
    int            print_close_msg = 0;

    tc_hmac_key_env = getenv("TC_HMAC_KEY");
    if(tc_hmac_key_env != NULL && tc_hmac_key_env[0] != '\0')
    {
        if(set_active_hmac_key((const uint8_t *)tc_hmac_key_env,
                               strlen(tc_hmac_key_env)) != 0)
        {
            fprintf(stderr, "Failed to initialise active HMAC key\n");
            goto error;
        }
    }
    else if(reset_active_hmac_key() != 0)
    {
        fprintf(stderr, "Failed to reset active HMAC key\n");
        goto error;
    }

    /* ------------------------------------------------------------------
     * Open input and output files
     * ------------------------------------------------------------------ */
    in_file = fopen(INPUT_FILE, "rb");
    if(in_file == NULL)
    {
        fprintf(stderr, "Failed to open input file: %s\n", INPUT_FILE);
        goto error;
    }

    out_file = fopen(OUTPUT_FILE, "wb");
    if(out_file == NULL)
    {
        fprintf(stderr, "Failed to open output file: %s\n", OUTPUT_FILE);
        goto close_input;
    }

    /* ------------------------------------------------------------------
     * Initialise the GSE de-encapsulator
     * ------------------------------------------------------------------ */
    status = gse_deencap_init(QOS_NBR, &deencap);
    if(status != GSE_STATUS_OK)
    {
        fprintf(stderr, "Failed to initialise GSE library: %s\n",
                gse_get_status(status));
        goto close_output;
    }

    /* ------------------------------------------------------------------
     * Read and de-encapsulate GSE packets one at a time.
     *
     * GSE packet layout (first 2 bytes):
     *   Bit 15    : S flag (start of PDU)
     *   Bit 14    : E flag (end of PDU)
     *   Bits 13-12: Label Type
     *   Bits 11-0 : GSE_LENGTH (number of bytes following these 2 bytes)
     *
     * Total packet size = 2 + GSE_LENGTH
     * ------------------------------------------------------------------ */
    while(fread(hdr, 1, 2, in_file) == 2)
    {
        /* Extract GSE_LENGTH from the lower 12 bits of the 2-byte header */
        remainder_len = ((uint16_t)(hdr[0] & 0x0F) << 8) | hdr[1];

        /* Allocate a buffer for the full GSE packet */
        raw_pkt = malloc(2 + remainder_len);
        if(raw_pkt == NULL)
        {
            fprintf(stderr, "Out of memory\n");
            goto release_lib;
        }

        /* Copy the 2 header bytes already read, then read the remainder */
        raw_pkt[0] = hdr[0];
        raw_pkt[1] = hdr[1];

        if(remainder_len > 0 &&
           fread(raw_pkt + 2, 1, remainder_len, in_file) != remainder_len)
        {
            fprintf(stderr, "Truncated GSE packet in input file\n");
            free(raw_pkt);
            goto release_lib;
        }

        pkt_count++;
        DEBUG(VERBOSE, "GSE packet #%d read: %u bytes total\n",
              pkt_count, 2 + remainder_len);

        /* Wrap the raw bytes in a virtual fragment for the library */
        status = gse_create_vfrag_with_data(&gse_packet,
                                            2 + remainder_len,
                                            GSE_MAX_HEADER_LENGTH,
                                            GSE_MAX_TRAILER_LENGTH,
                                            raw_pkt,
                                            2 + remainder_len);
        free(raw_pkt);
        raw_pkt = NULL;

        if(status != GSE_STATUS_OK)
        {
            fprintf(stderr, "Failed to create virtual fragment: %s\n",
                    gse_get_status(status));
            goto release_lib;
        }

        /* De-encapsulate — strips the GSE header and reassembles the PDU */
        status = gse_deencap_packet(gse_packet, deencap, &label_type, label,
                                    &protocol, &pdu, &gse_length);

        if(status != GSE_STATUS_OK &&
           status != GSE_STATUS_PDU_RECEIVED &&
           status != GSE_STATUS_DATA_OVERWRITTEN)
        {
            fprintf(stderr, "De-encapsulation error on packet #%d: %s\n",
                    pkt_count, gse_get_status(status));
            goto free_pdu;
        }

        /* PDU fully reassembled — write the payload to the output file */
        if(status == GSE_STATUS_PDU_RECEIVED)
        {
            size_t msg_len;
            int hmac_match;
            int rotation_applied = 0;
            uint8_t ack_flags = 0;
            uint8_t tc_service_type_id = 0;
            uint8_t tc_message_subtype_id = 0;
            uint16_t tc_message_counter = 0;

            print_release_msg = 0;
            print_close_msg = 0;

            pdu_count++;

            if(unpack_packet((const uint8_t *)pdu->start,
                             pdu->length,
                             SHA256_HASH_SIZE,
                             &tc_payload,
                             &tc_payload_len,
                             &tc_hmac) != 0)
            {
                fprintf(stderr, "Failed to unpack de-encapsulated TC payload\n");
                goto free_pdu;
            }

            hmac_match = verify_packet_hmac(tc_payload,
                                            tc_payload_len,
                                            tc_hmac,
                                            SHA256_HASH_SIZE);
            if(hmac_match < 0)
            {
                fprintf(stderr, "Failed to verify unpacked TC HMAC\n");
                goto free_pdu;
            }

            if(hmac_match == 0)
            {
                fprintf(stderr, "Packet discarded due to HMAC mismatch\n");
                goto free_pdu;
            }

            DEBUG(VERBOSE, "PDU #%d recovered: %zu bytes | "
                  "label type: %d | protocol: 0x%04X\n",
                  pdu_count, pdu->length, label_type, protocol);

            if(tc_payload_len >= 5)
            {
                ack_flags = (uint8_t)((tc_payload[0] >> 4) & 0x0F);
                tc_service_type_id = (uint8_t)(((tc_payload[0] & 0x0F) << 4) |
                                               ((tc_payload[1] & 0xF0) >> 4));
                tc_message_subtype_id = (uint8_t)(((tc_payload[1] & 0x0F) << 4) |
                                                  ((tc_payload[2] & 0xF0) >> 4));
                tc_message_counter =
                    ((uint16_t)(tc_payload[2] & 0x0F) << 12) |
                    ((uint16_t)tc_payload[3] << 4) |
                    ((uint16_t)(tc_payload[4] & 0xF0) >> 4);

                    //This prints out the recovered TC header fields and task started if ACK flag bit 2 is set high.
                DEBUG(VERBOSE,
                      "Recovered TC header fields: serviceTypeID=%u, messageSubtypeID=%u, TC messageCounter=%u\n",
                      (unsigned int)tc_service_type_id,
                      (unsigned int)tc_message_subtype_id,
                      (unsigned int)tc_message_counter);

                if((ack_flags & 0x4u) != 0)
                    DEBUG(VERBOSE, "Task Started: Output file is open\n");

                print_release_msg = ((ack_flags & 0x2u) != 0);
                print_close_msg = ((ack_flags & 0x1u) != 0);

                msg_len = tc_payload_len - 5;
                if(tc_message_subtype_id == 3)
                {
                    if(msg_len == 0)
                    {
                        DEBUG(VERBOSE,
                              "HMAC rotation skipped: message payload is empty\n");
                    }
                    else if(set_active_hmac_key(tc_payload + 5, msg_len) != 0)
                    {
                        DEBUG(VERBOSE,
                              "HMAC rotation skipped: failed to store the new key\n");
                    }
                    else
                    {
                        rotation_applied = 1;
                        DEBUG(VERBOSE,
                              "HMAC rotation applied for future packets\n");
                    }
                }
            }
            else
            {
                msg_len = 0;
            }

            if((ack_flags & 0x8u) != 0)
                DEBUG(VERBOSE, "Recovered TC HMAC valid: true\n");

            if(tc_payload_len >= 5)
            {
                DEBUG(VERBOSE, "Recovered TC message: %.*s\n",
                      (int)msg_len, (const char *)(tc_payload + 5));
                if(rotation_applied)
                {
                    DEBUG(VERBOSE,
                          "Rotation source message accepted for counter %u\n",
                          (unsigned int)tc_message_counter);
                }
            }
            else
            {
                DEBUG(VERBOSE, "Recovered TC payload too short for header\n");
            }

            free(tc_payload);
            free(tc_hmac);
            tc_payload = NULL;
            tc_hmac = NULL;
            tc_payload_len = 0;

            if(fwrite(pdu->start, 1, pdu->length, out_file) != pdu->length)
            {
                fprintf(stderr, "File write error\n");
                goto free_pdu;
            }

            status = gse_free_vfrag(&pdu);
            if(status != GSE_STATUS_OK)
            {
                fprintf(stderr, "Failed to free PDU: %s\n",
                        gse_get_status(status));
                goto release_lib;
            }
        }
    }

    DEBUG(VERBOSE, "Done. %d GSE packet(s) read, %d PDU(s) recovered. "
          "Output written to %s\n", pkt_count, pdu_count, OUTPUT_FILE);

    is_failure = 0;

    /* ------------------------------------------------------------------
     * Cleanup — reverse order of acquisition
     * ------------------------------------------------------------------ */
free_pdu:
    free(tc_payload);
    free(tc_hmac);
    if(pdu != NULL)
    {
        status = gse_free_vfrag(&pdu);
        if(status != GSE_STATUS_OK)
        {
            is_failure = 1;
            fprintf(stderr, "Failed to free PDU: %s\n", gse_get_status(status));
        }
    }
release_lib:
    status = gse_deencap_release(deencap);
    if(status != GSE_STATUS_OK)
    {
        is_failure = 1;
        fprintf(stderr, "Failed to release GSE library: %s\n",
                gse_get_status(status));
    }
    else if(print_release_msg)
    {
        DEBUG(VERBOSE, "Task In Progress: De-encapsulation library released\n");
    }
close_output:
    fclose(out_file);
    if(print_close_msg)
    {
        DEBUG(VERBOSE, "Task Complete: Write file closed\n");
    }
close_input:
    fclose(in_file);
error:
    return is_failure;
}