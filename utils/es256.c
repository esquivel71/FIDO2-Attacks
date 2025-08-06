/*
 * Copyright (c) 2018-2021 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <fido.h>
#include <fido/es256.h>
#include <cbor/data.h>
#include <fido/types.h>
#include <cbor.h>
#include <string.h>
#include "cbor.h"
#include "es256.h"

void
freezero(void *ptr, size_t sz)
{
	if (ptr == NULL)
		return;
	explicit_bzero(ptr, sz);
	free(ptr);
}

static int
decode_coord(const cbor_item_t *item, void *xy, size_t xy_len)
{
	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false ||
	    cbor_bytestring_length(item) != xy_len) {
		return (-1);
	}

	memcpy(xy, cbor_bytestring_handle(item), xy_len);

	return (0);
}

static int
decode_pubkey_point(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	es256_pk_t *k = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 1: /* x coordinate */
		return (decode_coord(val, &k->x, sizeof(k->x)));
	case 2: /* y coordinate */
		return (decode_coord(val, &k->y, sizeof(k->y)));
	}

	return (0); /* ignore */
}

int
es256_pk_decode_mod(const cbor_item_t *item, es256_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_pubkey_point) < 0) {
		return (-1);
	}

	return (0);
}

es256_sk_t *
es256_sk_new_mod(void)
{
	return (calloc(1, sizeof(es256_sk_t)));
}

void
es256_sk_free_mod(es256_sk_t **skp)
{
	es256_sk_t *sk;

	if (skp == NULL || (sk = *skp) == NULL)
		return;

	freezero(sk, sizeof(*sk));
	*skp = NULL;
}

es256_pk_t *
es256_pk_new_mod(void)
{
	return (calloc(1, sizeof(es256_pk_t)));
}

void
es256_pk_free_mod(es256_pk_t **pkp)
{
	es256_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

int
es256_sk_create_mod(es256_sk_t *key)
{
	EVP_PKEY_CTX	*pctx = NULL;
	EVP_PKEY_CTX	*kctx = NULL;
	EVP_PKEY	*p = NULL;
	EVP_PKEY	*k = NULL;
	const EC_KEY	*ec;
	const BIGNUM	*d;
	const int	 nid = NID_X9_62_prime256v1;
	int		 n;
	int		 ok = -1;

	if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL ||
	    EVP_PKEY_paramgen_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0 ||
	    EVP_PKEY_paramgen(pctx, &p) <= 0) {
		goto fail;
	}

	if ((kctx = EVP_PKEY_CTX_new(p, NULL)) == NULL ||
	    EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &k) <= 0) {
		goto fail;
	}

	if ((ec = EVP_PKEY_get0_EC_KEY(k)) == NULL ||
	    (d = EC_KEY_get0_private_key(ec)) == NULL ||
	    (n = BN_num_bytes(d)) < 0 || (size_t)n > sizeof(key->d) ||
	    (n = BN_bn2bin(d, key->d)) < 0 || (size_t)n > sizeof(key->d)) {
		goto fail;
	}

	ok = 0;
fail:
	if (p != NULL)
		EVP_PKEY_free(p);
	if (k != NULL)
		EVP_PKEY_free(k);
	if (pctx != NULL)
		EVP_PKEY_CTX_free(pctx);
	if (kctx != NULL)
		EVP_PKEY_CTX_free(kctx);

	return (ok);
}

int
es256_derive_pk_mod(const es256_sk_t *sk, es256_pk_t *pk)
{
	BIGNUM		*d = NULL;
	EC_KEY		*ec = NULL;
	EC_POINT	*q = NULL;
	const EC_GROUP	*g = NULL;
	const int	 nid = NID_X9_62_prime256v1;
	int		 ok = -1;

	if ((d = BN_bin2bn(sk->d, (int)sizeof(sk->d), NULL)) == NULL ||
	    (ec = EC_KEY_new_by_curve_name(nid)) == NULL ||
	    (g = EC_KEY_get0_group(ec)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		goto fail;
	}

	if (EC_POINT_mul(g, q, d, NULL, NULL, NULL) == 0 ||
	    EC_KEY_set_public_key(ec, q) == 0 ||
	    es256_pk_from_EC_KEY(pk, ec) != FIDO_OK) {
		goto fail;
	}

	ok = 0;
fail:
	if (d != NULL)
		BN_clear_free(d);
	if (q != NULL)
		EC_POINT_free(q);
	if (ec != NULL)
		EC_KEY_free(ec);

	return (ok);
}

cbor_item_t *
es256_pk_encode_mod(const es256_pk_t *pk, int ecdh)
{
	cbor_item_t		*item = NULL;
	struct cbor_pair	 argv[5];
	int			 alg;
	int			 ok = -1;

	memset(argv, 0, sizeof(argv));

	if ((item = cbor_new_definite_map(5)) == NULL)
		goto fail;

	/* kty */
	if ((argv[0].key = cbor_build_uint8(1)) == NULL ||
	    (argv[0].value = cbor_build_uint8(2)) == NULL ||
	    !cbor_map_add(item, argv[0]))
		goto fail;

	/*
	 * "The COSEAlgorithmIdentifier used is -25 (ECDH-ES +
	 * HKDF-256) although this is NOT the algorithm actually
	 * used. Setting this to a different value may result in
	 * compatibility issues."
	 */
	if (ecdh)
		alg = COSE_ECDH_ES256;
	else
		alg = COSE_ES256;

	/* alg */
	if ((argv[1].key = cbor_build_uint8(3)) == NULL ||
	    (argv[1].value = cbor_build_negint8((uint8_t)(-alg - 1))) == NULL ||
	    !cbor_map_add(item, argv[1]))
		goto fail;

	/* crv */
	if ((argv[2].key = cbor_build_negint8(0)) == NULL ||
	    (argv[2].value = cbor_build_uint8(1)) == NULL ||
	    !cbor_map_add(item, argv[2]))
		goto fail;

	/* x */
	if ((argv[3].key = cbor_build_negint8(1)) == NULL ||
	    (argv[3].value = cbor_build_bytestring(pk->x,
	    sizeof(pk->x))) == NULL || !cbor_map_add(item, argv[3]))
		goto fail;

	/* y */
	if ((argv[4].key = cbor_build_negint8(2)) == NULL ||
	    (argv[4].value = cbor_build_bytestring(pk->y,
	    sizeof(pk->y))) == NULL || !cbor_map_add(item, argv[4]))
		goto fail;

	ok = 0;
fail:
	if (ok < 0) {
		if (item != NULL) {
			cbor_decref(&item);
			item = NULL;
		}
	}

	for (size_t i = 0; i < 5; i++) {
		if (argv[i].key)
			cbor_decref(&argv[i].key);
		if (argv[i].value)
			cbor_decref(&argv[i].value);
	}

	return (item);
}

EVP_PKEY *
es256_sk_to_EVP_PKEY_mod(const es256_sk_t *k)
{
	BN_CTX		*bnctx = NULL;
	EC_KEY		*ec = NULL;
	EVP_PKEY	*pkey = NULL;
	BIGNUM		*d = NULL;
	const int	 nid = NID_X9_62_prime256v1;
	int		 ok = -1;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;

	BN_CTX_start(bnctx);

	if ((d = BN_CTX_get(bnctx)) == NULL ||
	    BN_bin2bn(k->d, sizeof(k->d), d) == NULL) {
		goto fail;
	}

	if ((ec = EC_KEY_new_by_curve_name(nid)) == NULL ||
	    EC_KEY_set_private_key(ec, d) == 0) {
		goto fail;
	}

	if ((pkey = EVP_PKEY_new()) == NULL ||
	    EVP_PKEY_assign_EC_KEY(pkey, ec) == 0) {
		goto fail;
	}

	ec = NULL; /* at this point, ec belongs to evp */

	ok = 0;
fail:
	if (bnctx != NULL) {
		BN_CTX_end(bnctx);
		BN_CTX_free(bnctx);
	}

	if (ec != NULL)
		EC_KEY_free(ec);

	if (ok < 0 && pkey != NULL) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return (pkey);
}

static int
hkdf_sha256(uint8_t *key, char *info, fido_blob_t *secret)
{
	const EVP_MD *const_md;
	EVP_MD *md = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	size_t keylen = SHA256_DIGEST_LENGTH;
	uint8_t	salt[32];
	int ok = -1;

	memset(salt, 0, sizeof(salt));
	if (secret->len > INT_MAX || strlen(info) > INT_MAX) {
		fido_log_debug("%s: invalid param", __func__);
		goto fail;
	}
	if ((const_md = EVP_sha256()) == NULL ||
	    (md = EVP_MD_meth_dup(const_md)) == NULL ||
	    (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL) {
		fido_log_debug("%s: init", __func__);
		goto fail;
	}
	if (EVP_PKEY_derive_init(ctx) < 1 ||
	    EVP_PKEY_CTX_set_hkdf_md(ctx, md) < 1 ||
	    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) < 1 ||
	    EVP_PKEY_CTX_set1_hkdf_key(ctx, secret->ptr, (int)secret->len) < 1 ||
	    EVP_PKEY_CTX_add1_hkdf_info(ctx, (void *)info, (int)strlen(info)) < 1) {
		fido_log_debug("%s: EVP_PKEY_CTX", __func__);
		goto fail;
	}
	if (EVP_PKEY_derive(ctx, key, &keylen) < 1) {
		fido_log_debug("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (md != NULL)
		EVP_MD_meth_free(md);
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);

	return ok;
}

static int kdf(uint8_t prot, fido_blob_t *key, /* const */ fido_blob_t *secret)
{
	char hmac_info[] = "CTAP2 HMAC key"; /* const */
	char aes_info[] = "CTAP2 AES key"; /* const */

	switch (prot) {
		case CTAP_PIN_PROTOCOL1:
			/* use sha256 on the resulting secret */
			key->len = SHA256_DIGEST_LENGTH;
			if ((key->ptr = calloc(1, key->len)) == NULL ||
				SHA256(secret->ptr, secret->len, key->ptr) != key->ptr) {
				fido_log_debug("%s: SHA256", __func__);
				return -1;
			}
			break;
		case CTAP_PIN_PROTOCOL2:
			/* use two instances of hkdf-sha256 on the resulting secret */
			key->len = 2 * SHA256_DIGEST_LENGTH;
			if ((key->ptr = calloc(1, key->len)) == NULL ||
				hkdf_sha256(key->ptr, hmac_info, secret) < 0 ||
				hkdf_sha256(key->ptr + SHA256_DIGEST_LENGTH, aes_info,
				secret) < 0) {
				fido_log_debug("%s: hkdf", __func__);
				return -1;
			}
			break;
		default:
			fido_log_debug("%s: unknown pin protocol %u", __func__, prot);
			return -1;
	}

	return 0;
}

int do_ecdh_mod(const fido_dev_t* dev, const es256_sk_t *sk, const es256_pk_t *pk, fido_blob_t **ecdh, int override_protocol)
{
	EVP_PKEY *pk_evp = NULL;
	EVP_PKEY *sk_evp = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	fido_blob_t *secret = NULL;
	int ok = -1;

	*ecdh = NULL;
	if ((secret = fido_blob_new()) == NULL ||
	    (*ecdh = fido_blob_new()) == NULL)
		goto fail;
	if ((pk_evp = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (sk_evp = es256_sk_to_EVP_PKEY_mod(sk)) == NULL) {
		goto fail;
	}
	if ((ctx = EVP_PKEY_CTX_new(sk_evp, NULL)) == NULL ||
	    EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(ctx, pk_evp) <= 0) {
		goto fail;
	}
	if (EVP_PKEY_derive(ctx, NULL, &secret->len) <= 0 ||
	    (secret->ptr = calloc(1, secret->len)) == NULL ||
	    EVP_PKEY_derive(ctx, secret->ptr, &secret->len) <= 0) {
		goto fail;
	}

	if (kdf((dev == NULL) ? override_protocol : fido_dev_get_pin_protocol(dev), *ecdh, secret) < 0) {
		fido_log_debug("%s: kdf", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pk_evp != NULL)
		EVP_PKEY_free(pk_evp);
	if (sk_evp != NULL)
		EVP_PKEY_free(sk_evp);
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (ok < 0)
		fido_blob_free(ecdh);

	fido_blob_free(&secret);

	return ok;
}

// RS256 stuff, maybe put in new file

static int
decode_bignum(const cbor_item_t *item, void *ptr, size_t len)
{
	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false ||
	    cbor_bytestring_length(item) != len) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	memcpy(ptr, cbor_bytestring_handle(item), len);

	return (0);
}


static int
decode_rsa_pubkey(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	rs256_pk_t *k = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 0: /* modulus */
		return (decode_bignum(val, &k->n, sizeof(k->n)));
	case 1: /* public exponent */
		return (decode_bignum(val, &k->e, sizeof(k->e)));
	}

	return (0); /* ignore */
}

int rs256_pk_decode_mod(const cbor_item_t *item, rs256_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_rsa_pubkey) < 0) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

// EDDSA stuff, maybe put in new file?

int eddsa_pk_decode_mod(const cbor_item_t *item, eddsa_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_pubkey_point) < 0) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}