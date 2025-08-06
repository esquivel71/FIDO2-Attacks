#ifndef _IO_H
#define _IO_H

#include "fido_utils.h"
#include "utils.h"

// static int tx_pkt(fido_dev_t *d, const void *pkt, size_t len, int *ms);

// static int
// tx_empty(fido_dev_t *d, uint8_t cmd, int *ms);

// static size_t
// tx_preamble(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count, int *ms);

// static size_t
// tx_frame(fido_dev_t *d, uint8_t seq, const void *buf, size_t count, int *ms);

// static int
// tx(fido_dev_t *d, uint8_t cmd, const unsigned char *buf, size_t count, int *ms);

// static int
// transport_tx(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count, int *ms);

int
fido_tx(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count, int *ms);

// static int
// rx_frame(fido_dev_t *d, struct frame *fp, int *ms);

// static int rx_preamble(fido_dev_t *d, uint8_t cmd, struct frame *fp, int *ms);

// static int
// rx(fido_dev_t *d, uint8_t cmd, unsigned char *buf, size_t count, int *ms);

// static int
// transport_rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int *ms);

int
fido_rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int *ms);

int
fido_rx_cbor_status(fido_dev_t *d, int *ms);

#endif