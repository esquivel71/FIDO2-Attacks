#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <unistd.h>
#include <cbor.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <fido/types.h>
#include <fido.h>


#include "../utils/es256.h"
#include "../utils/aes256.h"
#include "hooked_funcions.h"
#include "types.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define CTAP_PIN_PROTOCOL1 1
#define CTAP_PIN_PROTOCOL2 2
#define SHA256_DIGEST_LENGTH 32

#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))

#ifndef HAVE_TIMESPECSUB
#define	timespecadd(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec >= 1000000000L) {			\
			(vsp)->tv_sec++;				\
			(vsp)->tv_nsec -= 1000000000L;			\
		}							\
	} while (0)

#define timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (0)

#define	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
	    ((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
	    ((tsp)->tv_sec cmp (usp)->tv_sec))
#endif

#define FRAME_INIT_DATA_LEN (CTAP_MAX_REPORT_LEN - CTAP_INIT_HEADER_LEN)
#define FRAME_CONT_DATA_LEN (CTAP_MAX_REPORT_LEN - CTAP_CONT_HEADER_LEN)

extern int allow_ppoll;
extern int global_fd;

/* internal device capability flags */
#define FIDO_DEV_PIN_SET	0x001
#define FIDO_DEV_PIN_UNSET	0x002
#define FIDO_DEV_CRED_PROT	0x004
#define FIDO_DEV_CREDMAN	0x008
#define FIDO_DEV_PIN_PROTOCOL1	0x010
#define FIDO_DEV_PIN_PROTOCOL2	0x020
#define FIDO_DEV_UV_SET 	0x040
#define FIDO_DEV_UV_UNSET	0x080
#define FIDO_DEV_TOKEN_PERMS	0x100
#define FIDO_DEV_WINHELLO	0x200

// CTAP_CBOR_CLIENT_PIN sub-commands
#define CLIENT_PIN_GET_PIN_RETRIES   0X01
#define CLIENT_PIN_KEY_EXCHANGE		 0x02
#define CLIENT_PIN_SET_PIN		     0x03
#define CLIENT_PIN_CHANGE_PIN		 0x04
#define CLIENT_PIN_GET_PIN_TOKEN     0x05
#define CLIENT_PIN_GET_PIN_TOKEN_UV  0x06
#define CLIENT_PIN_GET_UV_RETRIES    0x07
#define CLIENT_PIN_GET_PIN_TOKEN_PIN 0x09    


#define CTAP21_UV_TOKEN_PERM_MAKECRED	0x01
#define CTAP21_UV_TOKEN_PERM_ASSERT	0x02
#define CTAP21_UV_TOKEN_PERM_CRED_MGMT	0x04
#define CTAP21_UV_TOKEN_PERM_BIO	0x08
#define CTAP21_UV_TOKEN_PERM_LARGEBLOB	0x10
#define CTAP21_UV_TOKEN_PERM_CONFIG	0x20

#define _FIDO_INTERNAL
#define FIDO_NO_DIAGNOSTIC

/* log */
#ifdef FIDO_NO_DIAGNOSTIC
#define fido_log_init(...)	do { /* nothing */ } while (0)
#define fido_log_debug(...)	do { /* nothing */ } while (0)
#define fido_log_xxd(...)	do { /* nothing */ } while (0)
#define fido_log_error(...)	do { /* nothing */ } while (0)
#else
#ifdef __GNUC__
void fido_log_init(void);
void fido_log_debug(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)));
void fido_log_xxd(const void *, size_t, const char *, ...)
    __attribute__((__format__ (printf, 3, 4)));
void fido_log_error(int, const char *, ...)
    __attribute__((__format__ (printf, 2, 3)));
#else
void fido_log_init(void);
void fido_log_debug(const char *, ...);
void fido_log_xxd(const void *, size_t, const char *, ...);
void fido_log_error(int, const char *, ...);
#endif /* __GNUC__ */
#endif /* FIDO_NO_DIAGNOSTIC */

#if !defined(HAVE_RECALLOCARRAY)

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

void * recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size);

#endif

int intToString (int value, char* result);

void printUnsignedChar (const unsigned char* data, ssize_t len, unsigned char* delimiter);

int file_exists(char* filename);

int file_exists_v2(char* filename);

int replace_authkey (unsigned char* cbor_data, size_t cbor_data_len, es256_pk_t *pk_for_libfido, unsigned char* new_cbor_data);

int hook_this_read_v1(int fd, size_t count);
int hook_this_read_v2(int fd, size_t count);
int hook_this_read_v3(int fd, size_t count);
int hook_this_read_v4(int fd, size_t count);

int hook_this_write(int fd, size_t count);

// static size_t
// tx_preamble(state_helper_t* d, uint8_t cmd, const void *buf, size_t count, int *ms,
//     int (*real_write)(int fd, const void *buf, size_t count));

// static size_t
// tx_frame(state_helper_t *d, uint8_t seq, const void *buf, size_t count, int *ms,
//     int (*real_write)(int fd, const void *buf, size_t count));

int
send_frames(state_helper_t *d, uint8_t cmd, const unsigned char *buf, size_t count, int *ms,
    int (*real_write)(int fd, const void *buf, size_t count));

// static int
// rx_frame(state_helper_t *d, struct frame *fp, int *ms,
//     int (*real_read)(int fd, void *buf, size_t count));

// static int
// rx_preamble(state_helper_t *d, uint8_t cmd, struct frame *fp, int *ms,
//     int (*real_read)(int fd, void *buf, size_t count));

int
read_frames(state_helper_t *d, uint8_t cmd, unsigned char *buf, size_t count, int *ms,
    int (*real_read)(int fd, void *buf, size_t count));

int find_token_name (int fd, char* token_name);

int list_tokens(fido_dev_info_t* devlist, size_t *ndevs);

int get_token_path(char* token_path);

int get_bad_token_path(char* bad_token_path, int select_higher);

int cbor_decrypt_then_encrypt (fido_blob_t* decrypt_key, fido_blob_t* encrypt_key, cbor_item_t* source, cbor_item_t** dest, int protocol);

/*

    This method changes CBOR data by decrypting info with one shared secret and encrypting with another.
    This is used to change the payload from client to token so that the token can decrypt it
    Data to change (depending on sub-command being used):

        -- Set Pin (0x03)
            - argv[2] -> encoded token public key: we need to use our own
            - argv[3] -> hmac with shared secret on newPinEnc || pinHashEnc (need new HMAC with new key)
            - argv[4] -> newPinEnc (new pin encrypted with shared secret): decrypt then encrypt with shared secret
        -- Change Pin (0x04)
            - argv[2] -> encoded token public key: we need to use our own
            - argv[3] -> hmac with shared secret on newPinEnc || pinHashEnc (need new HMAC with new key)
            - argv[4] -> newPinEnc (new pin encrypted with shared secret): decrypt then encrypt with shared secret
            - argv[5] -> pinHashEnc (old pin hashed with SHA256 and encrypted with shared secret): decrypt, then encrypt with new shared secret
        -- Get PinToken (0x05)
            - argv[2] -> encoded token public key: we need to use our own
            - argv[5] -> encrypted PIN (pin encrypted with shared secret): decrypt then encrypt with new shared secret
*/

fido_blob_t* modify_cbor_payload (unsigned char* cbor_payload, size_t cbor_len, fido_blob_t *shared_secret_1, state_helper_t* helper_read);

void printFrame (frame_t *fp, int count);

int msleep(long msec);

int string_read(FILE *f, char **out);

int fido_buf_read(const unsigned char **buf, size_t *len, void *dst, size_t count);

int fido_buf_write(unsigned char **buf, size_t *len, const void *src, size_t count);

/*

Logging functions.

*/

void xxd(const void *buf, size_t count);

void errx(int eval, const char *fmt, ...);

void attack_log(const char*, ...);

// void fido_log_debug(const char* format, ...);

// void fido_log_error(int error_no, const char* format, ...);

#endif