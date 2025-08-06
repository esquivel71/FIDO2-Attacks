# FIDO2 Attacks

This repository contains the source code for the Impersonation and Rogue key attacks described in this paper: https://dl.acm.org/doi/10.1145/3600160.3600174. Additionally, it also contains an implementation of a third attack (Double Registration) which is mentioned in the paper and allows an attacker to register its token alongside the user's. Specific code for each attack is located inside the respective attack's folder, and general utilities are located under **utils**.

To build the attack, call ```make``` in the root folder. Alternatively, to build each attack, run the build script inside its respective folder.

## Deploying through terminal

After building, each attack can be launched through the ```launch_attack.sh``` script, which loads the libraries into ```LD_PRELOAD```, sets up the relevant settings for the attack, and launches Google Chrome into the webauthn.io website.

When running the impersonation attack, for example, the script assumes the existence of a default "user73" username already registered in webauthn.io in the auhtenticator currently being used. Then, we just need to attempt to login  normally to another existing user. If the authenticator flashes to prove user presence twice, then the attack was performed. In the terminal, if the message "Attack completed successfully" appears, then the impersonation login with user73 succeeded.

It is also possible to replace user73 with any other already registered user by running ```launch_attack.sh -u USERNAME```.

## Deploying via LibreOffice macro

When opening the .ods file in the respective attack, if macros are allowed to run, it will automatically download a modified .desktop file for Google Chrome,which sets up the attack in the same way as ```launch_attack.sh``` whenever Chrome is opened. The malicious library and the auxiliary libraries are downloaded into /tmp.

## Future plans

Future plans include setting up a Docker with all dependencies for quickly building and deploying the attacks.