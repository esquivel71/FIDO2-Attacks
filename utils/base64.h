/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _BASE64_H
#define _BASE64_H

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef struct blob {
	unsigned char *ptr;
	size_t len;
} blob_t;

int base64_encode(const void *ptr, size_t len, char **out);

int base64_decode(const char *in, void **ptr, size_t *len);

int base64_read(FILE *f, blob_t *out);

#endif