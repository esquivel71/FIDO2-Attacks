#include <unistd.h>

#ifndef _FILENAMES_H
#define _FILENAMES_H

// Name of the file that will contain the helper structure, which keeps the current state of the hook/attack
char attack_helper_filename[40] = "/tmp/attack/.attack_helper";

// This is just a file that must exist for the rogue key attack to take place, otherwise the code should just keep out of the way
char swap_filename[40] = "/tmp/attack/.swap";

// This is just a file that must exist for the MITM attack to take place, otherwise the code should just keep out of the way
char mitm_filename[40] = "/tmp/attack/.mitm";

// This is just a file that must exist for the impersonation attack to take place, otherwise the code should just keep out of the way
char rogue_login_filename[40] = "/tmp/attack/.rogue_login";

char clean_up_filename[40] = "/tmp/attack/.cleanup";

char pin_token_filename[40] = "/tmp/attack/.stolen_pin_token";

// Master file that must be present for anything to happen
char master_file_filename[40] = "/tmp/attack/.master_file";

// Input file with assert data from the Python script
char assert_input_filename[40] = "/tmp/attack/assert_input_file.txt";

// Assert response data to be loaded by the Python script
char assert_response_filename[40] = "/tmp/attack/assert_response.txt";

char token_public_key_cbor_filename[40] = "/tmp/attack/.token_public_key_cbor";

char secret_key_1_filename[40] = "/tmp/attack/.secret_key_1";

#endif