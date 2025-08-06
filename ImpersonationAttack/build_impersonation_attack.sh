#!/bin/bash

FILE="impersonation_attack"
ATTACK_LOG=""
DEBUG=""

while getopts :lg flag
do
    case "${flag}" in
        l) ATTACK_LOG="-DATTACK_LOG";;
        g) DEBUG="-g";;
    esac
done

set -x

gcc $FILE.c ../utils/es256.c ../utils/cbor.c ../utils/utils.c ../utils/blob.c ../utils/aes256.c ../utils/fido_utils.c ../utils/token_operations.c ../utils/authkey.c ../utils/io.c ../utils/base64.c $DEBUG -o $FILE.so -fPIC -shared -ldl -L../auxlibs -lcbor -L../auxlibs -lfido2-2023 -D_GNU_SOURCE $ATTACK_LOG

rm $FILE.zip

zip $FILE.zip -j ./scripts/webauthn_io_authenticate.py ../auxlibs/libcrypto.so ../auxlibs/libfido2-2023.so ../auxlibs/libcbor.so ./$FILE.so

set +x
