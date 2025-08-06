#ifndef _AUTHKEY_H
#define _AUTHKEY_H

#include "../utils/utils.h"
#include "cbor.h"
#include "io.h"

static int parse_authkey_static(const cbor_item_t *key, const cbor_item_t *val, void *arg);

static int fido_dev_authkey_tx(fido_dev_t *dev, int *ms);

static int fido_dev_authkey_rx(fido_dev_t *dev, es256_pk_t *authkey, int *ms);

static int fido_dev_authkey_wait(fido_dev_t *dev, es256_pk_t *authkey, int *ms);

int fido_dev_authkey(fido_dev_t *dev, es256_pk_t *authkey, int *ms);

#endif