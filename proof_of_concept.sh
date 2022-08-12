#!/bin/bash

# ~~        ~~ #
GR="\033[32m"
FN="\033[0m"
# ~~        ~~ #

# generate flawed certs.
python3 generate.py 2>/dev/null # ~~ cortesía del compañero jarredon en 42Málaga ~~ #
echo -e ${GR}"-->"${FN}  "generated two certificates"
openssl x509 -pubkey -noout -in cert1.pem > pubkey.pem
echo -e ${GR}"-->"${FN}  "extracted public key from first cert."

# encrypt file
echo "congrats :)" > raw_file.txt
openssl rsautl -encrypt -inkey pubkey.pem -pubin -in raw_file.txt -out encrypted_file.enc
echo -e ${GR}"-->"${FN}  "encrypted file with public key"

# cleanup
rm raw_file.txt pubkey.pem

# crack key
echo -e ${GR}"-->"${FN}  "compile coRSAir..."
make && ./coRSAir cert1.pem cert2.pem

# decrypt file
echo -e ${GR}"-->"${FN}  "decrypt file with new private key:"
openssl rsautl -decrypt -inkey cracked_pkey.pem -in encrypted_file.enc > decrypted_file.txt
cat decrypted_file.txt

# cleanup 2
rm cert1.pem cert2.pem
make fclean
