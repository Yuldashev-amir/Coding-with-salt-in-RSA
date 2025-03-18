// programmingSaltRSA.c
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#define KEY_LENGTH 2048
#define SALT_SIZE 4
#define MD5_SIZE 16

int main()
{
	printf("OpenSSL connecting! \n");
	printf("Very Good! \n");
	return 0;
}
