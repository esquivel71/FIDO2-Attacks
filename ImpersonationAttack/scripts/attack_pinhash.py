#!/usr/bin/python3

import base64, hashlib, os, sys
from time import time
from string import printable
from itertools import product, count

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGIJKLMNOPQRSTUVWXYZ0123456789 %_-@"

def compare_bytes (b1, b2):

    if (len(b1) != len(b2)):
        return False

    for i,_ in enumerate(b1):
        if b1[i] != b2[i]:
            return False

    return True

def passwords(min_len, max_len, encoding):
    chars = [c.encode(encoding) for c in characters]
    for length in range(min_len, max_len):
        for pwd in product(chars, repeat=length):
            yield b''.join(pwd)


def crack(search_hash, min_len = 4, max_len = 63, encoding = 'utf-8'):
    for pwd in passwords(min_len, max_len, encoding):
        print(f"Trying PIN {pwd}")
        if hashlib.sha256(pwd).digest()[:16] == search_hash:
            return pwd.decode(encoding)


def run():

    num_of_args = len(sys.argv)
    min_length = 4
    max_length = 5

    if (num_of_args < 2):
        filename = "/tmp/attack/.pinhash"
    elif (num_of_args == 2):
        filename = sys.argv[1]
    else:
        print("Too many arguments! Exiting...")
        exit(-1)


    print(f"\nAttacking Pin Hash stored in file [{filename}]!")

    try:
        with open(filename, "rb") as pinhash_file:
            pinhash = pinhash_file.read()
    except:
        print(f"File [{filename}] does not exist, aborting...")
        exit(-1)
        
    if (len(pinhash) != 16):
        print(f"Pinhash does not have the correct length (length is {len(pinhash)}, should be 16)!")
        exit(-1)

    start = time()
    pin = crack(pinhash, min_length, max_length)
    end = time()

    print(f"PIN cracked: {pin}")
    print(f"Time: {end - start} seconds.")

    return

    sha256 = hashlib.sha256()    

    for pin_length in range(min_length, max_length):

        pin = bytearray(pin_length)

        for i in range(0, pin_length):

            for j in range (0, i + 1):

                for b in range(0, 255):
                    pin[pin_length - i - 1] = b
                    sha256.update(pin)
                    print(f"Trying {pin}")
                    if (compare_bytes(pinhash, sha256.digest()[:16])):
                        print(f"Found PIN! Here it is: {pin.decode('utf-8')}")
                        exit(0)

                pin[pin_length - i - 1] = 0

            
    print("Did not find any matching PIN!")           
            


    # print(f"Pinhash: {str(base64.b64encode(pinhash))}")

    # sample = "blue"
    # sample_bytes = sample.encode('utf-8')

    # sha256 = hashlib.sha256()
    # sha256.update(sample_bytes)
    # sample_hashed = sha256.digest()

    # print(f"Hash for \"blue\": {str(base64.b64encode(sample_hashed[:16]))}")

    # print(str(base64.b64encode(sample_hashed[:16])) == str(base64.b64encode(pinhash)))


    

if __name__ == "__main__":
    run()