#ifndef _IMPERSONATION_ATTACK_H
#define _IMPERSONATION_ATTACK_H

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <fido.h>
#include <string.h>
#include <cbor.h>
#include <errno.h>
#include <locale.h>
#include <limits.h>
#include <math.h>

#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include <linux/hidraw.h>
#include <linux/input.h>

#include <libudev.h>
#include <fido/es256.h> 
#include <poll.h>

#include "../utils/es256.h"
#include "../utils/cbor.h"
#include "../utils/utils.h"
#include "../utils/aes256.h"
#include "../utils/fido_utils.h"
#include "../utils/token_operations.h"
#include "../utils/filenames.h"


//Constants needed for the attack

const int token_pub_key_start_index = 3;

const int token_pin_token_start_index = 1;

#endif