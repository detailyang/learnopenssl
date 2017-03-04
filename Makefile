CC := cc
CFLAGS := -g -Wall -lssl -lcrypto
LINK := $(CC)
INCS := 

client: client.c
	$(CC) $? -o $@ $(CFLAGS) $(INCS)

errorcode: errorcode.c
	$(CC) $? -o $@ $(CFLAGS) $(INCS)
cert:
	bash ./generate-openssl.sh
