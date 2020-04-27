# fernet_cli
Simple CLI wrapper script for encrypting / decrypting data via the Fernet scheme.
For more information about Fernet see: https://github.com/fernet/spec/

# Features
* Based on cryptography.fernet, so should run almost everywhere
* Can encrypt / decrypt single strings/data via comand line
* Can encrypt tokens (```%mysecret%```) in files via ```--encrypt-file```

# TODO
* Implement full file decryption / encryption
* Implement help
* Implement self test
