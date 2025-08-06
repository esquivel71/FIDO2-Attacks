/*

This file contains functions to be used to communicate with the attack (bad) token in the TokenSwapAttack.

Many variables/functions/types defined in the libfido2 lib are not directly accessible in the library, so they are defined here.

If another way is found later, these definitions can be removed.

However, using the libfido2 source code here means it is less dependant on having the lib instaled in the system, which is always better.

*/

#ifndef _TOKEN_OPERATIONS_H
#define _TOKEN_OPERATIONS_H
//#define _FIDO_INTERNAL

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fido/types.h>
#include <fido/err.h>
#include <fido/param.h>
#include <linux/hid.h>
#include <linux/types.h>

#include "fido_utils.h"
#include "../utils/utils.h"
#include "authkey.h"


/*



*/

int get_dev_file_descriptor(fido_dev_t *dev);

fido_dev_t *open_bad_token();
fido_dev_t *open_user_token();



/*

Below are modified functions from the libfido2 library, meant to change some behavior needed to correctly apply the attack.

*/

int fido_dev_get_assert_mod(fido_dev_t *dev, fido_assert_t *assert, fido_blob_t* pin_token);

int fido_dev_make_cred_mod(fido_dev_t *dev, fido_cred_t *cred, fido_blob_t* pin_token);

fido_dev_t *fido_dev_new_mod(void);

fido_dev_t *open_dev_mod(const char *path);

int fido_do_ecdh_mod(fido_dev_t *dev, es256_pk_t **pk, fido_blob_t **ecdh, int *ms);

int fido_dev_get_uv_token(fido_dev_t *dev, uint8_t cmd, const char *pin, const fido_blob_t *ecdh, const es256_pk_t *pk, const char *rpid, fido_blob_t *token, int *ms);

int get_pin_token(state_helper_t *helper);

#endif