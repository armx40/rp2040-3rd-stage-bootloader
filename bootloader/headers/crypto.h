#include <stdint.h>

#ifndef HEADERS_CRYPTO_H_
#define HEADERS_CRYPTO_H_

#define CRYPTO_AES_BLOCK_SIZE 16
#define CRYPTO_TAG "CRYPTO"
#define CRYPTO_BUFFER_LEN 1024
#define CRYPTO_PLAINTEXT_BUFFER_LEN 1024
#define CRYPTO_CIPHER_BUFFER_LEN 1024

#define CRYPTO_USE_PSA
// #define CRYPTO_USE_ATECC

typedef enum
{
    CRYPTO_AES_BACKEND_ATECC608B,
} crypto_aes_backend_t;


typedef enum
{
    CRYPTO_AES_OPERATION_ENCRYPT,
    CRYPTO_AES_OPERATION_DECRYPT,
} crypto_aes_operation_t;

typedef struct crypto_exec_data_t
{
    int error;
    uint8_t *cipher;
    uint16_t cipher_len;
    uint8_t *plaintext;
    uint16_t plaintext_len;
    uint16_t out_len;
    uint8_t *iv;
    uint16_t iv_len;
    uint8_t *key;
    uint16_t key_len;
    uint8_t padding_size;
    crypto_aes_backend_t backend;
    crypto_aes_operation_t operation;

} crypto_exec_data_t;

int crypto_encrypt_cbc(crypto_exec_data_t *crypto_exec_data);
int crypto_decrypt_cbc(crypto_exec_data_t *crypto_exec_data);
int crypto_hmac(crypto_exec_data_t *crypto_exec_data);
int crypto_sha256(uint8_t *data, int data_len, uint8_t *hash, uint16_t hash_len);
int crypto_random(uint8_t *rand, uint16_t rand_len);
int crypto_ecdsa(crypto_exec_data_t *crypto_exec_data);
int crypto_init();
int crypto_verify_sign_from_hash(uint8_t *hash_to_verify, int hash_to_verify_len, uint8_t *signature, int signature_len);
int crypto_sign_hash(uint8_t *hash_to_sign, int hash_to_sign_length, uint8_t *signature, int signature_length,size_t *signature_written_size, uint8_t *ecc_private_key, int ecc_private_key_length );
// int crypto_encrypt_cbc(uint8_t *iv, uint8_t iv_len, uint8_t *pt, uint16_t pt_len, uint8_t *ct, uint16_t ct_len, uint8_t *key, uint16_t key_len, crypto_aes_backend_t backend, uint16_t *out_len);

// int crypto_decrypt_cbc(uint8_t *iv, uint8_t iv_len, uint8_t *pt, uint16_t pt_len, uint8_t *ct, uint16_t ct_len, uint8_t *key, uint16_t key_len, crypto_aes_backend_t backend, uint16_t *out_len);
#endif /* HEADERS_CRYPTO_H_ */
