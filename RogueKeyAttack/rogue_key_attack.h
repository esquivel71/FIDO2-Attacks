#ifndef _ROGUE_KEY_ATTACK_H
#define _ROGUE_KEY_ATTACK_H

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

// Name of the file that will contain the helper structure, which keeps the current state of the hook/attack
char swap_helper_filename[40] = "/tmp/attack/.swap_helper";

// This is just a file that must exist for the attack to take place, otherwise the code should just keep out of the way
char swap_filename[40] = "/tmp/attack/.swap";

char master_file_filename[40] = "/tmp/attack/.master_file";

#endif