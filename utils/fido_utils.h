#ifndef _FIDO_UTILS_H
#define _FIDO_UTILS_H

#include <string.h>
#include <cbor.h>   
#include <linux/hidraw.h>
#include <linux/input.h>
#include <sys/file.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <openssl/sha.h>

#include "utils.h"
#include "base64.h"

#define IOCTL_REQ(x)	(x)

#define TOKEN_OPT	"CDGILPRSVabcdefi:k:l:m:n:p:ru"

#define FLAG_DEBUG	0x01
#define FLAG_QUIET	0x02
#define FLAG_RK		0x04
#define FLAG_UV		0x08
#define FLAG_U2F	0x10
#define FLAG_HMAC	0x20
#define FLAG_UP		0x40
#define FLAG_LARGEBLOB	0x80

#define PINBUF_LEN	256

struct toggle {
	fido_opt_t up;
	fido_opt_t uv;
	fido_opt_t pin;
};


struct hid_linux {
	int             fd;
	size_t          report_in_len;
	size_t          report_out_len;
	sigset_t        sigmask;
	const sigset_t *sigmaskp;
};

extern int global_file_descriptor;

int get_key_len(uint8_t tag, uint8_t *key, size_t *key_len);


int get_key_val(const void *body, size_t key_len, uint32_t *val);

int fido_hid_get_usage(const uint8_t *report_ptr, size_t report_len, uint32_t *usage_page);

int fido_hid_get_report_len(const uint8_t *report_ptr, size_t report_len, size_t *report_in_len, size_t *report_out_len);

static int get_report_descriptor(int fd, struct hidraw_report_descriptor *hrd);

int is_fido(int fd);

int is_fido_try(int fd, size_t count);

uint8_t fido_dev_get_pin_protocol(const fido_dev_t *dev);

int fido_time_now(struct timespec *ts_now);

int fido_time_delta(const struct timespec *ts_start, int *ms_remain);

bool fido_dev_supports_permissions(const fido_dev_t *dev);

int fido_sha256(fido_blob_t *digest, const u_char *data, size_t data_len);

fido_assert_t *prepare_assert(FILE *in_f, int flags, const struct toggle *opt);

fido_cred_t *prepare_cred(FILE *in_f, int type, int flags);

/*

Below this block are the functions for dealing with the FIDO token directly.

*/

int fido_hid_unix_wait(int fd, int ms, const fido_sigset_t *sigmask);


void *fido_hid_open(const char *path);

void fido_hid_close(void *handle);

int fido_hid_real_read(void *handle, unsigned char *buf, size_t len, int ms);

int fido_hid_real_write(void *handle, const unsigned char *buf, size_t len);

#endif