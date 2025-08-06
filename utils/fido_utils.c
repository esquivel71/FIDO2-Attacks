#include "fido_utils.h"

int
get_key_len(uint8_t tag, uint8_t *key, size_t *key_len)
{
	*key = tag & 0xfc;
	if ((*key & 0xf0) == 0xf0) {
		return (-1);
	}

	*key_len = tag & 0x3;
	if (*key_len == 3) {
		*key_len = 4;
	}

	return (0);
}


int
get_key_val(const void *body, size_t key_len, uint32_t *val)
{
	const uint8_t *ptr = body;

	switch (key_len) {
	case 0:
		*val = 0;
		break;
	case 1:
		*val = ptr[0];
		break;
	case 2:
		*val = (uint32_t)((ptr[1] << 8) | ptr[0]);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
fido_hid_get_report_len(const uint8_t *report_ptr, size_t report_len,
    size_t *report_in_len, size_t *report_out_len)
{
	const uint8_t	*ptr = report_ptr;
	size_t		 len = report_len;
	uint32_t	 report_size = 0;

	while (len > 0) {
		const uint8_t tag = ptr[0];
		ptr++;
		len--;

		uint8_t  key;
		size_t   key_len;
		uint32_t key_val;

		if (get_key_len(tag, &key, &key_len) < 0 || key_len > len ||
		    get_key_val(ptr, key_len, &key_val) < 0) {
			return (-1);
		}

		if (key == 0x94) {
			report_size = key_val;
		} else if (key == 0x80) {
			*report_in_len = (size_t)report_size;
		} else if (key == 0x90) {
			*report_out_len = (size_t)report_size;
		}

		ptr += key_len;
		len -= key_len;
	}

	return (0);
}

int
fido_hid_get_usage(const uint8_t *report_ptr, size_t report_len,
    uint32_t *usage_page)
{
	const uint8_t	*ptr = report_ptr;
	size_t		 len = report_len;

	while (len > 0) {
		const uint8_t tag = ptr[0];
		ptr++;
		len--;

		uint8_t  key;
		size_t   key_len;
		uint32_t key_val;

		if (get_key_len(tag, &key, &key_len) < 0 || key_len > len ||
		    get_key_val(ptr, key_len, &key_val) < 0) {
			return (-1);
		}

		if (key == 0x4) {
			*usage_page = key_val;
		}

		ptr += key_len;
		len -= key_len;
	}

	return (0);
}

static int
get_report_descriptor(int fd, struct hidraw_report_descriptor *hrd)
{
	int s = -1;

	if (ioctl(fd, IOCTL_REQ(HIDIOCGRDESCSIZE), &s) == -1) {
		return (-1);
	}

	if (s < 0 || (unsigned)s > HID_MAX_DESCRIPTOR_SIZE) {
		return (-1);
	}

	hrd->size = (unsigned)s;

	if (ioctl(fd, IOCTL_REQ(HIDIOCGRDESC), hrd) == -1) {
		return (-1);
	}

	return (0);
}

int is_fido(int fd)	
{
	uint32_t usage_page = 0;
	struct hidraw_report_descriptor	hrd;

	memset(&hrd, 0, sizeof(hrd));

	if (get_report_descriptor(fd, &hrd) < 0 ||
	    fido_hid_get_usage(hrd.value, hrd.size, &usage_page) < 0)
		usage_page = 0;

	int isFido = usage_page == 0xf1d0;

	return isFido;
}

int is_fido_try(int fd, size_t count) {

	int new_fido = 1;

	if (new_fido) {
		frame_t *fp;
		
		return count == sizeof(*fp) + 1 && is_fido(fd);
	}
	else {
		return is_fido(fd);
	}
	
}

uint8_t fido_dev_get_pin_protocol(const fido_dev_t *dev)
{
	if (dev->flags & FIDO_DEV_PIN_PROTOCOL2)
		return (CTAP_PIN_PROTOCOL2);
	else if (dev->flags & FIDO_DEV_PIN_PROTOCOL1)
		return (CTAP_PIN_PROTOCOL1);

	return (0);
}

int fido_time_now(struct timespec *ts_now)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts_now) != 0) {
		fido_log_error(errno, "%s: clock_gettime", __func__);
		return -1;
	}

	return 0;
}

static int timespec_to_ms(const struct timespec *ts)
{
	int64_t x, y;

	if (ts->tv_sec < 0 || ts->tv_nsec < 0 ||
	    ts->tv_nsec >= 1000000000LL)
		return -1;

	if ((uint64_t)ts->tv_sec >= INT64_MAX / 1000LL)
		return -1;

	x = ts->tv_sec * 1000LL;
	y = ts->tv_nsec / 1000000LL;

	if (INT64_MAX - x < y || x + y > INT_MAX)
		return -1;

	return (int)(x + y);
}

int
fido_time_delta(const struct timespec *ts_start, int *ms_remain)
{
	struct timespec ts_end, ts_delta;
	int ms;

	if (*ms_remain < 0)
		return 0;

	if (clock_gettime(CLOCK_MONOTONIC, &ts_end) != 0) {
		fido_log_error(errno, "%s: clock_gettime", __func__);
		return -1;
	}

	if (timespeccmp(&ts_end, ts_start, <)) {
		fido_log_debug("%s: timespeccmp", __func__);
		return -1;
	}

	timespecsub(&ts_end, ts_start, &ts_delta);

	if ((ms = timespec_to_ms(&ts_delta)) < 0) {
		fido_log_debug("%s: timespec_to_ms", __func__);
		return -1;
	}

	if (ms > *ms_remain)
		ms = *ms_remain;

	*ms_remain -= ms;

	return 0;
}

bool fido_dev_supports_permissions(const fido_dev_t *dev)
{
	return (dev->flags & FIDO_DEV_TOKEN_PERMS);
}

int fido_sha256(fido_blob_t *digest, const u_char *data, size_t data_len)
{
	if ((digest->ptr = calloc(1, SHA256_DIGEST_LENGTH)) == NULL)
		return (-1);

	digest->len = SHA256_DIGEST_LENGTH;

	if (SHA256(data, data_len, digest->ptr) != digest->ptr) {
		fido_blob_reset(digest);
		return (-1);
	}

	return (0);
}

fido_assert_t *
prepare_assert(FILE *in_f, int flags, const struct toggle *opt)
{
	fido_assert_t *assert = NULL;
	struct blob cdh;
	struct blob id;
	struct blob hmac_salt;
	char *rpid = NULL;
	int r;

	memset(&cdh, 0, sizeof(cdh));
	memset(&id, 0, sizeof(id));
	memset(&hmac_salt, 0, sizeof(hmac_salt));

	r = base64_read(in_f, &cdh);
	r |= string_read(in_f, &rpid);
	if ((flags & FLAG_RK) == 0)
		r |= base64_read(in_f, &id);
	if (flags & FLAG_HMAC)
		r |= base64_read(in_f, &hmac_salt);
	if (r < 0)
		errx(1, "input error");

	if (flags & FLAG_DEBUG) {
		fprintf(stderr, "client data hash:\n");
		xxd(cdh.ptr, cdh.len);
		fprintf(stderr, "relying party id: %s\n", rpid);
		if ((flags & FLAG_RK) == 0) {
			fprintf(stderr, "credential id:\n");
			xxd(id.ptr, id.len);
		}
		// fprintf(stderr, "up=%s\n", opt2str(opt->up));
		// fprintf(stderr, "uv=%s\n", opt2str(opt->uv));
		// fprintf(stderr, "pin=%s\n", opt2str(opt->pin));
	}

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	if ((r = fido_assert_set_clientdata_hash(assert, cdh.ptr,
	    cdh.len)) != FIDO_OK ||
	    (r = fido_assert_set_rp(assert, rpid)) != FIDO_OK)
		errx(1, "fido_assert_set: %s", fido_strerr(r));
	if ((r = fido_assert_set_up(assert, opt->up)) != FIDO_OK)
		errx(1, "fido_assert_set_up: %s", fido_strerr(r));
	if ((r = fido_assert_set_uv(assert, opt->uv)) != FIDO_OK)
		errx(1, "fido_assert_set_uv: %s", fido_strerr(r));

	if (flags & FLAG_HMAC) {
		if ((r = fido_assert_set_extensions(assert,
		    FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
			errx(1, "fido_assert_set_extensions: %s",
			    fido_strerr(r));
		if ((r = fido_assert_set_hmac_salt(assert, hmac_salt.ptr,
		    hmac_salt.len)) != FIDO_OK)
			errx(1, "fido_assert_set_hmac_salt: %s",
			    fido_strerr(r));
	}
	if (flags & FLAG_LARGEBLOB) {
		if ((r = fido_assert_set_extensions(assert,
		    FIDO_EXT_LARGEBLOB_KEY)) != FIDO_OK)
			errx(1, "fido_assert_set_extensions: %s", fido_strerr(r));
	}
	if ((flags & FLAG_RK) == 0) {
		if ((r = fido_assert_allow_cred(assert, id.ptr,
		    id.len)) != FIDO_OK)
			errx(1, "fido_assert_allow_cred: %s", fido_strerr(r));
	}

	free(hmac_salt.ptr);
	free(cdh.ptr);
	free(id.ptr);
	free(rpid);

	return (assert);
}

fido_cred_t *
prepare_cred(FILE *in_f, int type, int flags)
{
	fido_cred_t *cred = NULL;
	struct blob cdh;
	struct blob uid;
	char *rpid = NULL;
	char *uname = NULL;
	int r;

	memset(&cdh, 0, sizeof(cdh));
	memset(&uid, 0, sizeof(uid));

	r = base64_read(in_f, &cdh);
	r |= string_read(in_f, &rpid);
	r |= string_read(in_f, &uname);
	r |= base64_read(in_f, &uid);
	if (r < 0)
		errx(1, "input error");

	if (flags & FLAG_DEBUG) {
		fprintf(stderr, "client data hash:\n");
		xxd(cdh.ptr, cdh.len);
		fprintf(stderr, "relying party id: %s\n", rpid);
		fprintf(stderr, "user name: %s\n", uname);
		fprintf(stderr, "user id:\n");
		xxd(uid.ptr, uid.len);
	}

	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");

	if ((r = fido_cred_set_type(cred, type)) != FIDO_OK ||
	    (r = fido_cred_set_clientdata_hash(cred, cdh.ptr,
	    cdh.len)) != FIDO_OK ||
	    (r = fido_cred_set_rp(cred, rpid, NULL)) != FIDO_OK ||
	    (r = fido_cred_set_user(cred, uid.ptr, uid.len, uname, NULL,
	    NULL)) != FIDO_OK)
		errx(1, "fido_cred_set: %s", fido_strerr(r));

	if (flags & FLAG_RK) {
		if ((r = fido_cred_set_rk(cred, FIDO_OPT_TRUE)) != FIDO_OK)
			errx(1, "fido_cred_set_rk: %s", fido_strerr(r));
	}
	if (flags & FLAG_UV) {
		if ((r = fido_cred_set_uv(cred, FIDO_OPT_TRUE)) != FIDO_OK)
			errx(1, "fido_cred_set_uv: %s", fido_strerr(r));
	}
	if (flags & FLAG_HMAC) {
		if ((r = fido_cred_set_extensions(cred,
		    FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
			errx(1, "fido_cred_set_extensions: %s", fido_strerr(r));
	}
	if (flags & FLAG_LARGEBLOB) {
		if ((r = fido_cred_set_extensions(cred,
		    FIDO_EXT_LARGEBLOB_KEY)) != FIDO_OK)
			errx(1, "fido_cred_set_extensions: %s", fido_strerr(r));
	}

	free(cdh.ptr);
	free(uid.ptr);
	free(rpid);
	free(uname);

	return (cred);
}


/*

Below this block are the functions for dealing with the FIDO token directly.

*/

int fido_hid_unix_wait(int fd, int ms, const fido_sigset_t *sigmask)
{
	struct timespec ts;
	struct pollfd pfd;
	int r;

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN;
	pfd.fd = fd;

#ifdef FIDO_FUZZ
	return (0);
#endif
	if (ms > -1) {
		ts.tv_sec = ms / 1000;
		ts.tv_nsec = (ms % 1000) * 1000000;
	}

	if ((r = ppoll(&pfd, 1, ms > -1 ? &ts : NULL, sigmask)) < 1) {
		if (r == -1)
			attack_log("%s: ppoll. Error: %d (%s)\n", __func__, errno, strerror(errno));
		return (-1);
	}

	return (0);
}


void *fido_hid_open(const char *path)
{
	struct hid_linux *ctx;
	struct hidraw_report_descriptor hrd;
	struct timespec tv_pause;
	long interval_ms, retries = 0;

	ctx = calloc(1, sizeof(*ctx));

	// This is an overwrite to avoid opening the token again, since it might block in the "flock" call.
	// Instead, we take the file_descriptor, which will have been set in the write and read hooks, and use that as if we had opened the token.
	if (global_file_descriptor < 1) {
		if ((ctx == NULL) ||
			(ctx->fd = open(path, O_RDWR)) == -1) {
			free(ctx);
			return (NULL);
		}

		while (flock(ctx->fd, LOCK_EX|LOCK_NB) == -1) {
			attack_log("STUCK IN LOOP INSIDE CUSTOM OPEN! ERRNO: %d (%s)\n", errno, strerror(errno));
			if (errno != EWOULDBLOCK) {
				fido_hid_close(ctx);
				return (NULL);
			}
			if (retries++ >= 15) {
				attack_log("retries++ >= 15\n");
				fido_hid_close(ctx);
				return (NULL);
			}
			interval_ms = retries * 100000000L;
			tv_pause.tv_sec = interval_ms / 1000000000L;
			tv_pause.tv_nsec = interval_ms % 1000000000L;
			if (nanosleep(&tv_pause, NULL) == -1) {
				fido_hid_close(ctx);
				return (NULL);
			}
		}
	}

	else {
		ctx->fd = global_file_descriptor;
	}
	
	if (get_report_descriptor(ctx->fd, &hrd) < 0 ||
		fido_hid_get_report_len(hrd.value, hrd.size, &ctx->report_in_len,
		&ctx->report_out_len) < 0 || ctx->report_in_len == 0 ||
		ctx->report_out_len == 0) {
		attack_log("%s: using default report sizes\n", __func__);
		ctx->report_in_len = CTAP_MAX_REPORT_LEN;
		ctx->report_out_len = CTAP_MAX_REPORT_LEN;
	}

	return (ctx);
}

void fido_hid_close(void *handle)
{
	struct hid_linux *ctx = handle;

	if (close(ctx->fd) == -1)
		attack_log("%s: close. Error: %d\n"	, __func__, errno);

	free(ctx);
}

int fido_hid_real_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct hid_linux	*ctx = handle;
	ssize_t			 r;

	if (len != ctx->report_in_len) {
		attack_log("%s: len %zu1n", __func__, len);
		return (-1);
	}

	if (fido_hid_unix_wait(ctx->fd, ms, ctx->sigmaskp) < 0) {
		attack_log("%s: fd not ready1n", __func__);
		return (-1);
	}

	if ((r = real_read(ctx->fd, buf, len)) == -1) {
		attack_log("%s: read. Error: %d1n", __func__, errno);
		return (-1);
	}

	if (r < 0 || (size_t)r != len) {
		attack_log("%s: %zd != %zu1n", __func__, r, len);
		return (-1);
	}

	return ((int)r);
}

int fido_hid_real_write(void *handle, const unsigned char *buf, size_t len)
{
	struct hid_linux	*ctx = handle;
	ssize_t			 r;

	if (len != ctx->report_out_len + 1) {
		attack_log("%s: len %zu\n", __func__, len);
		return (-1);
	}

	if ((r = real_write(ctx->fd, buf, len)) == -1) {
		attack_log("%s: write. Error: %d\n", __func__, errno);
		return (-1);
	}

	if (r < 0 || (size_t)r != len) {
		attack_log("%s: %zd != %zu\n", __func__, r, len);
		return (-1);
	}

	return ((int)r);
}