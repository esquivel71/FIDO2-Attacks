/*
 * Copyright (c) 2018-2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _CBOR_H
#define _CBOR_H

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <fido.h>
#include <cbor/data.h>
#include <cbor.h>
#include <string.h>

#include "utils.h"
#include "blob.h"

static int
check_key_type(cbor_item_t *item);

/*
 * Validate CTAP2 canonical CBOR encoding rules for maps.
 */
static int ctap_check_cbor(cbor_item_t *prev, cbor_item_t *curr);

int cbor_map_iter(const cbor_item_t *item, void *arg, int(*f)(const cbor_item_t *, const cbor_item_t *, void *));

int cbor_array_iter(const cbor_item_t *item, void *arg, int(*f)(const cbor_item_t *, void *));

int cbor_parse_reply(const unsigned char *blob, size_t blob_len, void *arg, int(*parser)(const cbor_item_t *, const cbor_item_t *, void *));

cbor_item_t * cbor_encode_change_pin_auth(uint8_t prot, const fido_blob_t *secret, const fido_blob_t *new_pin_enc, const fido_blob_t *pin_hash_enc);

cbor_item_t * cbor_encode_pin_auth(uint8_t prot, const fido_blob_t *secret, const fido_blob_t *data);

int cbor_bytestring_copy(const cbor_item_t *item, unsigned char **buf, size_t *len);

static int _pow(int b, int ex);

bool cbor_get_bool(const cbor_item_t *item);

static void _cbor_nested_describe(cbor_item_t *item, FILE *out, int indent);

void my_cbor_describe(cbor_item_t *item, FILE *out);

cbor_item_t *cbor_encode_pin_opt(const fido_dev_t *dev);


int cbor_add_bytestring(cbor_item_t *item, const char *key, const unsigned char *value, size_t value_len);

int cbor_add_string(cbor_item_t *item, const char *key, const char *value);

cbor_item_t * cbor_encode_pubkey(const fido_blob_t *pubkey);

cbor_item_t * cbor_encode_pubkey_list(const fido_blob_array_t *list);

cbor_item_t * cbor_encode_rp_entity(const fido_rp_t *rp);

cbor_item_t * cbor_encode_user_entity(const fido_user_t *user);

cbor_item_t * cbor_encode_pubkey_param(int cose_alg);

cbor_item_t * cbor_encode_cred_ext(const fido_cred_ext_t *ext, const fido_blob_t *blob);

cbor_item_t * cbor_encode_cred_opt(fido_opt_t rk, fido_opt_t uv);


int cbor_add_bool(cbor_item_t *item, const char *key, fido_opt_t value);

cbor_item_t * cbor_encode_assert_ext(fido_dev_t *dev, const fido_assert_ext_t *ext, const fido_blob_t *ecdh, const es256_pk_t *pk);


cbor_item_t * cbor_encode_assert_opt(fido_opt_t up, fido_opt_t uv);


int fido_assert_set_count(fido_assert_t *assert, size_t n);

int adjust_assert_count(const cbor_item_t *key, const cbor_item_t *val, void *arg);


int parse_authkey(const cbor_item_t *key, const cbor_item_t *val, void *arg);

int parse_uv_token(const cbor_item_t *key, const cbor_item_t *val, void *arg);

int parse_makecred_reply(const cbor_item_t *key, const cbor_item_t *val, void *arg);

int cbor_string_copy(const cbor_item_t *item, char **str);

int cbor_decode_user(const cbor_item_t *item, fido_user_t *user);

int cbor_decode_pubkey(const cbor_item_t *item, int *type, void *key);

int cbor_decode_fmt(const cbor_item_t *item, char **fmt);

int cbor_decode_cred_authdata(const cbor_item_t *item, int cose_alg, fido_blob_t *authdata_cbor, fido_authdata_t *authdata,
fido_attcred_t *attcred, fido_cred_ext_t *authdata_ext);

int cbor_decode_attstmt(const cbor_item_t *item, fido_attstmt_t *attstmt);

int cbor_decode_cred_id(const cbor_item_t *item, fido_blob_t *id);

int cbor_decode_assert_authdata(const cbor_item_t *item, fido_blob_t *authdata_cbor,
    fido_authdata_t *authdata, fido_assert_extattr_t *authdata_ext);

int parse_assert_reply(const cbor_item_t *key, const cbor_item_t *val, void *arg);

static int cbor_add_arg(cbor_item_t *item, uint8_t n, cbor_item_t *arg);

cbor_item_t *cbor_flatten_vector(cbor_item_t *argv[], size_t argc);

int cbor_build_frame(uint8_t cmd, cbor_item_t *argv[], size_t argc, fido_blob_t *f);

void cbor_vector_free(cbor_item_t **item, size_t len);

#endif