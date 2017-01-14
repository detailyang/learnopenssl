CC := cc
CFLAGS := -g -lssl -lcrypto
LINK := $(CC)
INCS := 

client: client.c
	$(CC) $? -o $@ $(CFLAGS) $(INCS)

cert:
	bash ./generate-openssl.sh
