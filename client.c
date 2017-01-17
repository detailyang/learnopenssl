/*
* @Author: detailyang
* @Date:   2017-01-14 20:21:55
* @Last Modified by:   detailyang
* @Last Modified time: 2017-01-17 23:49:52
*/

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>

#define dd(...) fprintf(stderr, "ssl %s: ", __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " OPENSSL: %s", ERR_reason_error_string(ERR_get_error())); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

int
SSL_CTX_use_PrivateKey_file_pass(SSL_CTX *ctx,char *filename,char *pass)
{
       BIO      *key=NULL;
       EVP_PKEY *pkey=NULL;

       key = BIO_new(BIO_s_file());
       BIO_read_filename(key, filename);

       pkey=PEM_read_bio_PrivateKey(key, NULL, NULL, pass);
       if(pkey == NULL) {
              printf("PEM_read_bio_PrivateKey err");
              return -1;
       }

       if (SSL_CTX_use_PrivateKey(ctx,pkey) <= 0) {
              printf("SSL_CTX_use_PrivateKey err\n");
              return -1;
       }

       BIO_free(key);

       return 1;
}


int main(int argc, char *argv[]) {
    int        		 i;
    BIO       		*bio, *out;
    SSL       		*ssl;
    char       		 buf[4096] = {0};
    char                 hostport[1024] = {0};
    SSL_CTX   		*ctx;
    X509      		*x509;
    X509_NAME 		*x509_name;
    X509_NAME 		*xn;
    STACK_OF(X509_NAME) *sk2;
    const SSL_CIPHER 	*c;

    if (argc < 3) {
	printf("Usage: ./client host port\r\n");
	exit(1);
    }

    sprintf(hostport, "%s:%s", argv[1], argv[2]);

    ERR_load_crypto_strings();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
	printf("new ssl ctx error");
	ERR_print_errors_fp(stderr);
	exit(1);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "./fixtures/ca.crt", NULL)) {
	printf("load ca certificate error");
	exit(1);
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (!SSL_use_certificate_file(ssl, "./fixtures/client.crt", SSL_FILETYPE_PEM)) {
	dd("use client certificate error");
	exit(1);
    }

    if (!SSL_use_PrivateKey_file(ssl, "./fixtures/client.unsecure.key", SSL_FILETYPE_PEM)) {
	dd("use client key error");
	exit(1);
    }

	printf("%s\r\n", hostport);
    BIO_set_conn_hostname(bio, hostport);

    if (BIO_do_connect(bio) <= 0) {
	dd("bio connection error");
	exit(1);
    }

    if(SSL_get_verify_result(ssl) != X509_V_OK) {
	   printf("server certificate verify error\n");
	   exit(1);
    }

    printf("server certificate verify success\n");
    x509 = SSL_get_peer_certificate(ssl);
    x509_name = X509_get_subject_name(x509);
    X509_NAME_print_ex(out, x509_name, 0, 0);
    BIO_printf(out, "\n");

    sk2 = SSL_get_client_CA_list(ssl);
    if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0)) {
	BIO_printf(out, "---\nAcceptable client certificate CA names\n");
    	for (i = 0; i < sk_X509_NAME_num(sk2); i++) {
	    xn = sk_X509_NAME_value(sk2, i);
	    X509_NAME_oneline(xn, buf, sizeof(buf));
	    BIO_write(out, buf, strlen(buf));
	    BIO_write(out, "\n", 1);
    	}
    } else {
	BIO_printf(out, "---\nNo client certificate CA names sent\n");
    }

    c = SSL_get_current_cipher(ssl);
    BIO_printf(out, "%s, Cipher is %s\n",
               SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));

    X509_free(x509);
    SSL_CTX_free(ctx);
    SSL_free(ssl);

    return 0;
}
