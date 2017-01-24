#! /bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )"
cd fixtures

SUBJECT="/C=US/ST=California/L=Mountain View/O=BlackBox Inc"
SUBJECT_CN="$SUBJECT/CN=$DOMAIN"

PASSWORD=${PASSWORD:-blackbox}

openssl genrsa -des3 -passout "pass:$PASSWORD" -out server.key 2048
openssl rsa -passin "pass:$PASSWORD" -in server.key -out server.unsecure.key
openssl req -passin "pass:$PASSWORD" -new -subj "$SUBJECT/CN=server" -key server.key -out server.csr

openssl ecparam -genkey -name secp256r1 | openssl ec -out ecc-server.key
openssl req -passin "pass:$PASSWORD" -new -subj "$SUBJECT/CN=ecc-server" -key ecc-server.key -out ecc-server.csr


openssl genrsa -des3 -passout "pass:$PASSWORD" -out client.key 2048
openssl rsa -passin "pass:$PASSWORD" -in client.key -out client.unsecure.key
openssl req -passin "pass:$PASSWORD" -new -subj "$SUBJECT/CN=client" -key client.key -out client.csr


openssl req -passin "pass:$PASSWORD" -passout "pass:$PASSWORD" -new -x509 -subj "$SUBJET/CN=ca"  -keyout ca.key -out ca.crt
openssl x509 -req -sha256 -days 30650 -passin "pass:$PASSWORD" -in client.csr  -CA ca.crt -CAkey ca.key -set_serial 1 -out client.crt
openssl x509 -req -sha256 -days 30650 -passin "pass:$PASSWORD" -in server.csr  -CA ca.crt -CAkey ca.key -set_serial 2 -out server.crt
openssl x509 -req -sha256 -days 30650 -passin "pass:$PASSWORD" -in ecc-server.csr  -CA ca.crt -CAkey ca.key -set_serial 3 -out ecc-server.crt


openssl pkcs12 -passin "pass:$PASSWORD" -passout "pass:$PASSWORD" -export -clcerts -in client.crt -inkey client.key -out client.p12
openssl pkcs12 -passin "pass:$PASSWORD" -passout "pass:$PASSWORD" -export -in client.crt -inkey client.key -out  client.pfx
openssl x509 -in client.crt -out client.cer
openssl x509 -in server.crt -out server.cer
openssl x509 -in ecc-server.crt -out ecc-server.cer

openssl genpkey -algorithm RSA -out rsa.key -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsa.key -out rsa.pub
