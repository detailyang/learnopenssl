#! /bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )"
cd fixtures

SUBJECT="/C=US/ST=California/L=Mountain View/O=Blackbox Inc"
SUBJECT_CN="$SUBJECT/CN=$DOMAIN"

openssl genrsa -des3 -out server.key 2048
openssl rsa -in server.key -out server.key

openssl req -new -subj "$SUBJECT/CN=server" -key server.key -out server.csr

openssl genrsa -des3 -out client.key 2048
openssl req -new -subj "$SUBJECT/CN=client" -key client.key -out client.csr

openssl req -new -x509 -subj "$SUBJET/CN=ca"  -keyout ca.key -out ca.crt

rm -rf /etc/pki/CA/index.txt
rm -rf /etc/pki/CA/serial
touch /etc/pki/CA/{index.txt,serial}
echo 01 > /etc/pki/CA/serial

openssl ca  -policy policy_anything -days 1460 -in server.csr -out server.crt -cert ca.crt -keyfile ca.key
openssl ca  -policy policy_anything -days 1460 -in client.csr -out client.crt -cert ca.crt -keyfile ca.key

openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12
openssl pkcs12 -export -in client.crt -inkey client.key -out  client.pfx
openssl x509 -in client.crt -out client.cer
openssl x509 -in server.crt -out server.cer
