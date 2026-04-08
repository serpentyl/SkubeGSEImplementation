/*
 * GSE encapsulation — raw memory input, binary file output
 *
 * Takes a payload defined as a hex byte array, encapsulates it
 * into GSE packets, and writes the resulting packets to a binary file.
 *
 * The output file contains back-to-back raw GSE packets.
 * Each packet is self-delimiting via the GSE length field in its header.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* GSE includes */
#include "GSE/libgse/src/encap/encap.h"
#include "GSE/libgse/src/common/constants.h"

/* TC header + HMAC packet builder */
#include "TCHeaderPack.h"

/* TC packet configuration */
#define DEFAULT_TC_HMAC_KEY "SkubeTradeshowDemoKey"
#define DEFAULT_TC_MESSAGE  "Testing Message"

/* -------------------------------------------------------------------------
 * Configuration — adjust these for your use case
 * ------------------------------------------------------------------------- */

/** Maximum number of QoS queues (1 is sufficient for a single stream) */
#define QOS_NBR     1

/** FIFO depth inside the GSE encapsulator (How many packets can be queued in memory) */
#define FIFO_SIZE   100

/** Protocol type tag — agreed upon between transmitter and receiver.
 *  Values 0x0600–0xFFFF are valid. Pick one that identifies your data. */
#define PROTOCOL    0x1234

/** Set to 0 to disable fragmentation (produces a single GSE packet).
 *  Set to a byte count to cap each GSE packet at that size. */
#define FRAG_LENGTH 0

/** Label type: 0 = 6-byte label, 1 = 3-byte, 2 = broadcast, 3 = re-use (Set to 2 for planned implementation) */
#define LABEL_TYPE  2

/** QoS queue index to use */
#define QOS         0

/** Output binary file path */
#define OUTPUT_FILE "gse_output.bin"

/** Debug printing: set to 1 to enable, 0 to disable */
#define VERBOSE     1

#define DEBUG(verbose, format, ...) \
  do { if(verbose) printf(format, ##__VA_ARGS__); } while(0)



/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    gse_encap_t  *encap     = NULL;
    gse_vfrag_t  *pdu       = NULL;
    gse_vfrag_t  *vfrag_pkt = NULL;
    gse_status_t  status;
    uint8_t       label[6];
    FILE         *out_file  = NULL;
    int           is_failure = 1;
    int           i;
    int           pkt_count = 0;

    unsigned char *in_packet = NULL;
    size_t         in_size   = 0;
    const char    *tc_hmac_key;
    const char    *tc_message;
    uint16_t       tc_counter = 1;

    if(argc == 4)
    {
        tc_message  = argv[1];
        tc_hmac_key = argv[2];
        tc_counter  = (uint16_t)atoi(argv[3]);
    }
    else if(argc == 1)
    {
        tc_message  = DEFAULT_TC_MESSAGE;
        tc_hmac_key = DEFAULT_TC_HMAC_KEY;
    }
    else
    {
        fprintf(stderr, "Usage: %s [<message> <hmac_key> <counter>]\n", argv[0]);
        return 1;
    }

    in_packet = build_tc_packet(tc_hmac_key, tc_message, tc_counter, &in_size, NULL);
    if(in_packet == NULL)
    {
        fprintf(stderr, "Failed to build TC packet\n");
        return 1;
    }

    DEBUG(VERBOSE, "Payload size: %zu bytes\n", in_size);

    /* ------------------------------------------------------------------
     * Open output file
     * ------------------------------------------------------------------ */
    out_file = fopen(OUTPUT_FILE, "wb");
    if(out_file == NULL)
    {
        fprintf(stderr, "Failed to open output file: %s\n", OUTPUT_FILE);
        goto error;
    }

    /* ------------------------------------------------------------------
     * Initialise the GSE encapsulator
     * ------------------------------------------------------------------ */
    status = gse_encap_init(QOS_NBR, FIFO_SIZE, &encap);
    if(status != GSE_STATUS_OK)
    {
        fprintf(stderr, "Failed to initialise GSE library: %s\n",
                gse_get_status(status));
        goto close_file;
    }

    /* ------------------------------------------------------------------
     * Build the label (IP type in header).
     * ------------------------------------------------------------------ */
    for(i = 0; i < gse_get_label_length(LABEL_TYPE); i++)
        label[i] = (uint8_t)i;

    /* ------------------------------------------------------------------
     * Create a virtual fragment from the raw payload.
     *
     * Head room (GSE_MAX_HEADER_LENGTH) is reserved at the front so the
     * encapsulator can prepend the GSE header without copying the data.
     * ------------------------------------------------------------------ */
    status = gse_create_vfrag_with_data(&pdu,
                                        in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet,
                                        in_size);
    if(status != GSE_STATUS_OK)
    {
        fprintf(stderr, "Failed to create virtual fragment: %s\n",
                gse_get_status(status));
        goto release_lib;
    }

    /* ------------------------------------------------------------------
     * Hand the PDU to the encapsulator.
     * Ownership of pdu passes to the library after this call.
     * ------------------------------------------------------------------ */
    status = gse_encap_receive_pdu(pdu, encap, label, LABEL_TYPE,
                                   PROTOCOL, QOS);
    if(status != GSE_STATUS_OK)
    {
        fprintf(stderr, "Failed to enqueue PDU: %s\n",
                gse_get_status(status));
        goto release_lib;
    }

    /* ------------------------------------------------------------------
     * Retrieve encapsulated GSE packet(s) and write to file.
     * The loop runs multiple times only when FRAG_LENGTH is set and
     * the payload is large enough to require fragmentation.
     * ------------------------------------------------------------------ */
    do
    {
        status = gse_encap_get_packet(&vfrag_pkt, encap, FRAG_LENGTH, QOS);

        if(status != GSE_STATUS_OK && status != GSE_STATUS_FIFO_EMPTY)
        {
            fprintf(stderr, "Failed to get GSE packet: %s\n",
                    gse_get_status(status));
            goto release_lib;
        }

        if(status != GSE_STATUS_FIFO_EMPTY)
        {
            /* Write raw GSE packet bytes to the output file */
            size_t written = fwrite(vfrag_pkt->start, 1,
                                    vfrag_pkt->length, out_file);
            if(written != vfrag_pkt->length)
            {
                fprintf(stderr, "File write error\n");
                goto release_lib;
            }

            pkt_count++;
            DEBUG(VERBOSE, "Packet %d written: %zu bytes\n",
                  pkt_count, vfrag_pkt->length);
        }
        else
        {
            DEBUG(VERBOSE, "Encapsulation complete - FIFO empty\n");
        }

        if(vfrag_pkt != NULL)
        {
            status = gse_free_vfrag(&vfrag_pkt);
            if(status != GSE_STATUS_OK && status != GSE_STATUS_FIFO_EMPTY)
            {
                fprintf(stderr, "Failed to free fragment: %s\n",
                        gse_get_status(status));
                goto release_lib;
            }
        }
    }
    while(status != GSE_STATUS_FIFO_EMPTY);

    DEBUG(VERBOSE, "Done. %d GSE packet(s) written to %s\n",
          pkt_count, OUTPUT_FILE);

    is_failure = 0;

    /* ------------------------------------------------------------------
     * Cleanup - Release resources
     * ------------------------------------------------------------------ */
release_lib:
    status = gse_encap_release(encap);
    if(status != GSE_STATUS_OK)
    {
        fprintf(stderr, "Failed to release GSE library: %s\n",
                gse_get_status(status));
        is_failure = 1;
    }
close_file:
    fclose(out_file);
error:
    free(in_packet);
    return is_failure;
}