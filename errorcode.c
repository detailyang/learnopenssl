#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
	SSL_CTX *ctx;
	EVP_PKEY    *key;
	unsigned long err;
	char buf[120] = {0};

    	ERR_load_crypto_strings();
    	SSL_load_error_strings();
    	ERR_load_BIO_strings();
    	OpenSSL_add_all_algorithms();

    	SSL_library_init();

    	ctx = SSL_CTX_new(SSLv23_client_method());
	if (SSL_CTX_use_PrivateKey(ctx, key) == 0) {
		printf("SSL_CTX_use_PrivateKey() failed\n");
		err = ERR_get_error();
		printf("openssl error code:%ld\n", err);
		/*
		 *  	char *ERR_error_string(unsigned long e, char *buf);
		 *   	void ERR_error_string_n(unsigned long e, char *buf, size_t len);
		 *    	const char *ERR_lib_error_string(unsigned long e);
		 *     	const char *ERR_func_error_string(unsigned long e);
		 *      const char *ERR_reason_error_string(unsigned long e);
		 */
		ERR_error_string_n(err, buf, 120);
		printf("ERR_error_string_n: %s\n", buf);
		printf("ERR_lib_error_string: %s\n", ERR_lib_error_string(err));
		printf("ERR_func_error_string: %s\n", ERR_func_error_string(err));
		printf("ERR_reason_error_string: %s\n", ERR_reason_error_string(err));
		return;
	}
	
	return 0;
}
