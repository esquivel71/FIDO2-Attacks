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
#include "../utils/base64.h"

// Name of the file that will contain the helper structure, which keeps the current state of the hook/attack
char swap_helper_filename[40] = "/tmp/attack/.swap_helper";

// Name of the file that will contain the helper structure, which keeps the current state of the hook/attack
char attack_helper_filename[40] = "/tmp/attack/.attack_helper";

// This is just a file that must exist for the rogue key attack to take place, otherwise the code should just keep out of the way
char swap_filename[40] = "/tmp/attack/.swap";

// This is just a file that must exist for the MITM attack to take place, otherwise the code should just keep out of the way
char mitm_filename[40] = "/tmp/attack/.mitm";

// This is just a file that must exist for the impersonation attack to take place, otherwise the code should just keep out of the way
char rogue_login_filename[40] = "/tmp/attack/.rogue_login";

char rogue_register_filename[40] = "/tmp/attack/.rogue_register";

char clean_up_filename[40] = "/tmp/attack/.cleanup";

char pin_token_filename[40] = "/tmp/attack/.stolen_pin_token";

// Master file that must be present for anything to happen
char master_file_filename[40] = "/tmp/attack/.master_file";

// Input file with register data from the Python script
char register_input_filename[40] = "/tmp/attack/register_input_file.txt";

// register response data to be loaded by the Python script
char register_response_filename[40] = "/tmp/attack/register_response.txt";

char token_public_key_cbor_filename[40] = "/tmp/attack/.token_public_key_cbor";

char secret_key_1_filename[40] = "/tmp/attack/.secret_key_1";


//Constants needed for the attack

const int token_pub_key_start_index = 3;

const int token_pin_token_start_index = 1;

#endif