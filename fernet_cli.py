#!/usr/bin/env python3

# Simple CLI wrapper script for encrypting / decrypting data via the 
# Fernet scheme (symmetric encryption).
# For more info visit: https://github.com/fernet/spec/blob/master/Spec.md

# Disclaimer: Use at your own risk. I'm by no means a crypto expert!

# Copyright (C) 2020 x86dev / Andreas Löffler
#  
# This script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# 
# This script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this script.  If not, see <http://www.gnu.org/licenses/>.

import fileinput
import getopt
import re
import os
import sys

import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def key_derive(password: bytes, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations, backend=default_backend())
    return b64e(kdf.derive(password))

def value_encrypt(message: bytes, password: str, iterations: int) -> bytes:
    salt = os.urandom(16)
    key = key_derive(password.encode(), salt, iterations)
    return b64e(b'%b%b%b' % (salt, iterations.to_bytes(4, 'big'), b64d(Fernet(key).encrypt(message)),))

def value_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = key_derive(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)

def replace_and_encrypt(re_match, password: str, iterations: int):
    value_plain = re_match.group(1)
    value_enc = value_encrypt(bytes(value_plain, 'utf-8'), password, iterations)
    value_dec = value_decrypt(value_enc, password)
    if bytearray(value_dec) == bytearray(value_plain, 'utf-8'):
        return ("%s" % (value_enc.decode('utf-8'),))
    return ("ERROR")

def print_help():
    print("No help yet, sorry.")

def main():

    try:
        aOpts, aArgs = getopt.gnu_getopt(sys.argv[1:], "hv", \
            [ "", "help", "decrypt=", "encrypt=", "encrypt-file", "password=" ])
    except getopt.error as msg:
        print(msg)
        print("For help use --help")
        sys.exit(2)

    cIterations  = 100_000
    fEncrypt     = None
    fEncryptFile = None
    aFilenames   = []

    for o, a in aOpts:
        if o in ("-d", "--decrypt"):
            fEncrypt = False
            sToken = a
        elif o in ("-e", "--encrypt"):
            fEncrypt = True
            sPlaintext = a
        elif o in ("-e", "--encrypt-file"):
            fEncryptFile = True
        elif o in ("-i", "--iter"):
            cIterations = int(a)
        elif o in ("-h", "--help"):
            print_help()
            sys.exit(0)
        elif o in ("-p", "--password"):
            sPassword = a
        else:
            print("Unknown option '%s'. Exiting." % (o,))
            sys.exit(2)

    if  fEncrypt is None \
    and fEncryptFile is None:
        print("No mode (decrypt / encrypt) specified")
        exit(2)

    if cIterations < 100_000:
        print("Warning: Less than 100.000 iterations are not recommended!")

    if fEncryptFile:
        aFilenames = aArgs
        if not len(aFilenames):
            print("No file name(s) specified")
            exit(2)

        for sFilename in aFilenames:
            with fileinput.FileInput(sFilename, inplace=False) as file:
                for line in file:
                    sys.stdout.write(re.sub(r'\%(.*)\%', lambda m: replace_and_encrypt(m, sPassword, cIterations), line))    
    elif fEncrypt:
        if not sPlaintext:
            print("Nothing to encrypt specified")
            exit(2)
        byEncrypted = value_encrypt(sPlaintext.encode(), sPassword, cIterations)
        print(byEncrypted.decode('utf-8'))
    else:
        if not sToken:
            print("Nothing to decrypt specified")
            exit(2)
        byDecrypted = value_decrypt(sToken.encode(), sPassword)
        print(byDecrypted.decode('utf-8'))
    
if __name__ == "__main__":
    main()
