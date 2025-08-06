/*
 * Copyright (c) 2018-2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _ES256_H
#define _ES256_H

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf.h>

#include <fido.h>
#include <fido/es256.h>
#include <cbor/data.h>
#include <fido/types.h>
#include <cbor.h>
#include <string.h>

#include "../utils/blob.h"
#include "fido_utils.h"
#include "types.h"

static int
decode_coord(const cbor_item_t *item, void *xy, size_t xy_len);

static int
decode_pubkey_point(const cbor_item_t *key, const cbor_item_t *val, void *arg);

int
es256_pk_decode_mod(const cbor_item_t *item, es256_pk_t *k);

es256_sk_t *
es256_sk_new_mod(void);

void
es256_sk_free_mod(es256_sk_t **skp);

es256_pk_t *
es256_pk_new_mod(void);

void
es256_pk_free_mod(es256_pk_t **pkp);

int
es256_sk_create_mod(es256_sk_t *key);

int
es256_derive_pk_mod(const es256_sk_t *sk, es256_pk_t *pk);

cbor_item_t *
es256_pk_encode_mod(const es256_pk_t *pk, int ecdh);

EVP_PKEY *
es256_sk_to_EVP_PKEY_mod(const es256_sk_t *k);

static int hkdf_sha256(uint8_t *key, char *info, fido_blob_t *secret);

static int kdf(uint8_t prot, fido_blob_t *key, /* const */ fido_blob_t *secret);

int do_ecdh_mod(const fido_dev_t *dev, const es256_sk_t *sk, const es256_pk_t *pk, fido_blob_t **ecdh, int override_protocol);

// RS256 stuff, maybe put in new file?

int rs256_pk_decode_mod(const cbor_item_t *item, rs256_pk_t *k);

// EDDSA stuff, maybe put in new file?

int eddsa_pk_decode_mod(const cbor_item_t *item, eddsa_pk_t *k);


#endif