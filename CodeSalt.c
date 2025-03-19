// programmingSaltRSA.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#define SALT_SIZE 4 // Размер соли (4 байта)

// Определяем соль (4 байта)
unsigned char salt[SALT_SIZE] = {0x76, 0x48, 0x2F, 0xAE};

struct __attribute__((packed)) newStruct
{
	float oneVal;
	float secVal;
	float thVal;
	float foVal;
	uint8_t minVal;
	uint16_t valOne16;
    uint16_t valTwo16;
}; 

// Функция вычисления MD5 с солью
void md5_with_salt(const struct newStruct * data, unsigned char * output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();  // Создаём контекст
    if(!ctx)
    {
        fprintf(stderr, "Unable to allocate memory for md5 context\n");
        return;
    }

    if(EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) // Инициализация MD5
    {
        fprintf(stderr, "Error of initialization MD5 \n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if(EVP_DigestUpdate(ctx, salt, SALT_SIZE) != 1)  // Добавляем соль
    {
        fprintf(stderr, "Error of add salt for coding \n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if(EVP_DigestUpdate(ctx, data, sizeof(&data)) != 1)  // Добавляем данные
    {
        fprintf(stderr, "Error add data for coding \n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if(EVP_DigestFinal_ex(ctx, output, NULL) != 1)  // Получаем итоговый хэш
    {
        fprintf(stderr, "Error initialization hash \n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    EVP_MD_CTX_free(ctx);  // Освобождаем память
}

// Функция вывода хэша в HEX-формате
void print_hash(unsigned char *hash) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]); // Выводим каждый байт в hex
    printf("\n");
}

int main() {
    // Данные для хеширования
    struct newStruct structExample = {4.4, 2.3, 5.2, 4.0, 8, 16};
 //   const char *input_data = "Hello, MD5!";
    unsigned char md5_hash[MD5_DIGEST_LENGTH]; // 16 байт MD5

    // Вычисляем MD5 с солью
    md5_with_salt(&structExample, md5_hash);

    // Вывод результата
    printf("MD5 coding pack struct with salt: ");
    print_hash(md5_hash);

    return 0;
}

