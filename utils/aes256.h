/*
 * Copyright (c) 2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _AES256_H
#define _AES256_H

#include "fido.h"
#include "blob.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>

#include "hooked_funcions.h"

static int
aes256_cbc(const fido_blob_t *key, const u_char *iv, const fido_blob_t *in,
    fido_blob_t *out, int encrypt);


static int
aes256_cbc_proto1(const fido_blob_t *key, const fido_blob_t *in,
    fido_blob_t *out, int encrypt);

static int
aes256_cbc_fips(const fido_blob_t *secret, const fido_blob_t *in,
    fido_blob_t *out, int encrypt);

static int
aes256_gcm(const fido_blob_t *key, const fido_blob_t *nonce,
    const fido_blob_t *aad, const fido_blob_t *in, fido_blob_t *out,
    int encrypt);

int
aes256_cbc_enc(int protocol, const fido_blob_t *secret,
    const fido_blob_t *in, fido_blob_t *out);

int
aes256_cbc_dec(int protocol, const fido_blob_t *secret,
    const fido_blob_t *in, fido_blob_t *out);

int
aes256_gcm_enc(const fido_blob_t *key, const fido_blob_t *nonce,
    const fido_blob_t *aad, const fido_blob_t *in, fido_blob_t *out);

int
aes256_gcm_dec(const fido_blob_t *key, const fido_blob_t *nonce,
    const fido_blob_t *aad, const fido_blob_t *in, fido_blob_t *out);


#endif // _AES256_H