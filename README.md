# coRSAir

From 42 cybersecurity bootcamp; create a tool that accepts two RSA certificates and attempts to generate a private key from one of them.  
  
This project serves as an introduction to asymmetric cryptography and its possible vulnerabilities.  
A certificate creator needs to generate public keys with random big prime numbers, if its number generator its weak and assigns the same prime number to two public keys due to low entropy in its system, this leaves those public keys vulnerable to an attack, as obtaining its secret numbers from the public modulus becomes a trivial task.  
  
coRSAir [ written in __C__ ], tries to extract the public keys from the two given certificates, and then checks if those are vulnerable to the attack. If true, it will recover the private key from the first public key, first getting its two prime numbers, then obtaining the __d__ exponent.  

## Dependencies
coRSAir makes use of __openssl__ API and libraries for C, so host machine must have them installed.
### MacOS
```
brew install openssl
```
### Debian/Ubuntu
```
apt install openssl
```

## Usage

### Proof of concept  
Will generate two vulnerable RSA certificates [ credits to @jarredon from 42 Málaga for the python script ], then it will encrypt a message with the private key from the first certificate.  
coRSAir will be compiled and executed with the two generated public keys, a private key for the first pk is created and used to decrypt the message, which will be printed at last.  
```
./proof_of_concept.sh
```

### Execution
```
make && ./coRSAir CERT1 CERT2
```
