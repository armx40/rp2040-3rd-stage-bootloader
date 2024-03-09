#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pico/stdlib.h"
#include "pico/rand.h"

#include "../headers/defines.h"
#include "../headers/debug.h"
#include "../headers/crypto.h"
#include "../headers/log.h"
#include "../headers/bootloader.h"

#include "psa/crypto.h"
#include "psa/crypto_extra.h"
#include "psa/crypto_values.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"

#include "../public_key.h"

uint8_t CRYPTO_CIPHER_BUFFER[CRYPTO_CIPHER_BUFFER_LEN] = {
    0,
};

uint8_t CRYPTO_PLAINTEXT_BUFFER[CRYPTO_PLAINTEXT_BUFFER_LEN] = {
    0,
};

int crypto_init()
{
    int err;
    psa_status_t stat = psa_crypto_init();
    if (stat != PSA_SUCCESS)
    {
        return SW_ERROR;
    }
    return SW_OK;
}

int crypto_get_cipher_buffer(uint8_t **buffer)
{
    *buffer = CRYPTO_CIPHER_BUFFER;
    return SW_OK;
}

int crypto_xor_blocks(uint8_t *a, uint8_t *b, uint8_t n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        a[i] = a[i] ^ b[i];
    }
    return SW_OK;
}

int crypto_encrypt_cbc(crypto_exec_data_t *crypto_exec_data)
{
    int err;
    if (crypto_exec_data->iv_len > CRYPTO_AES_BLOCK_SIZE)
    {
        return SW_ERROR;
    }

    if (crypto_exec_data->plaintext_len > CRYPTO_PLAINTEXT_BUFFER_LEN - CRYPTO_AES_BLOCK_SIZE)
    {
        return SW_ERROR;
    }

    uint8_t data_hex[2048] = {
        0,
    };

    uint8_t *data_to_encrypt = crypto_exec_data->plaintext;
    uint16_t data_to_encrypt_len = crypto_exec_data->plaintext_len;

    // essential_get_hex_string(data_to_encrypt, data_to_encrypt_len, data_hex, data_to_encrypt_len * 2, 1);
    // log_logd(CRYPTO_TAG, "aes buffer: %s", data_hex);
    // padding

    /* prepare data */
    memset(CRYPTO_PLAINTEXT_BUFFER, 0, CRYPTO_PLAINTEXT_BUFFER_LEN);
    memcpy(CRYPTO_PLAINTEXT_BUFFER, data_to_encrypt, data_to_encrypt_len);
    /* */

    /* pad the data */

    //  calculate bytes to add
    uint16_t padding_size = CRYPTO_AES_BLOCK_SIZE - (crypto_exec_data->plaintext_len % CRYPTO_AES_BLOCK_SIZE);
    int i;
    for (i = 0; i < padding_size; i++)
    {
        CRYPTO_PLAINTEXT_BUFFER[crypto_exec_data->plaintext_len + i] = padding_size;
    }

    data_to_encrypt = CRYPTO_PLAINTEXT_BUFFER;
    data_to_encrypt_len = crypto_exec_data->plaintext_len + padding_size;

    crypto_exec_data->padding_size = padding_size;
    /**/

    /* generate random iv */
    uint8_t rand_iv[16] = {
        0,
    };
    crypto_random(rand_iv, 16);
    memcpy(crypto_exec_data->iv, rand_iv, 16);
    crypto_exec_data->iv_len = 16;

    /* */

    /* prepare iv */

    uint8_t iv_[16] = {
        0,
    };
    memcpy(iv_, crypto_exec_data->iv, CRYPTO_AES_BLOCK_SIZE);
    uint8_t *iv = iv_;
    /**/

    // essential_get_hex_string(data_to_encrypt, data_to_encrypt_len, data_hex, data_to_encrypt_len * 2, 1);
    // log_logd(CRYPTO_TAG, "aes buffer: %s", data_hex);

    uint16_t blocks_num = (data_to_encrypt_len / CRYPTO_AES_BLOCK_SIZE);

    for (i = 0; i < blocks_num; i++)
    {
        // log_logw(CRYPTO_TAG, "block: %d", i);
        /* xor for cbc */
        crypto_xor_blocks(data_to_encrypt + (CRYPTO_AES_BLOCK_SIZE * i), iv, 16);
        /* */

#ifdef CRYPTO_USE_PSA
#endif

#ifdef CRYPTO_USE_ATECC
        err = atecc_aes_encrypt_block(data_to_encrypt + (CRYPTO_AES_BLOCK_SIZE * i), CRYPTO_AES_BLOCK_SIZE, CRYPTO_CIPHER_BUFFER + (CRYPTO_AES_BLOCK_SIZE * i), 0, 0);
        if (err != SW_OK)
        {
            log_loge(CRYPTO_TAG, "atecc failed");
            return SW_ERROR;
        }
#endif
        /**/

        /* change iv */
        iv = CRYPTO_CIPHER_BUFFER + (CRYPTO_AES_BLOCK_SIZE * i);
        /**/

        // sleep_ms(1000);
    }
    crypto_exec_data->cipher = CRYPTO_CIPHER_BUFFER;
    crypto_exec_data->cipher_len = data_to_encrypt_len;
    crypto_exec_data->out_len = data_to_encrypt_len;
    return SW_OK;
}

int crypto_decrypt_cbc(crypto_exec_data_t *crypto_exec_data)
{

    int err;
    if (crypto_exec_data->iv_len > CRYPTO_AES_BLOCK_SIZE)
    {
        return SW_ERROR;
    }

    // if (crypto_exec_data.pt_len > CRYPTO_BUFFER_LEN - 16)
    // {
    //     return SW_ERROR;
    // }

    if (crypto_exec_data->cipher_len % 16 != 0)
    {
        return SW_ERROR;
    }

    uint8_t data_hex[2048] = {
        0,
    };

    memset(CRYPTO_PLAINTEXT_BUFFER, 0, CRYPTO_PLAINTEXT_BUFFER_LEN);

    uint8_t *data_to_decrypt = crypto_exec_data->cipher;
    uint16_t data_to_decrypt_len = crypto_exec_data->cipher_len;

    // essential_get_hex_string(data_to_decrypt, data_to_decrypt_len, data_hex, data_to_decrypt_len * 2, 1);
    // log_logd(CRYPTO_TAG, "aes buffer: %s", data_hex);
    // padding

    /* prepare iv */
    uint8_t iv_[16] = {
        0,
    };
    memcpy(iv_, crypto_exec_data->iv, CRYPTO_AES_BLOCK_SIZE);
    uint8_t *iv = iv_;
    /**/

    uint16_t blocks_num = (data_to_decrypt_len / CRYPTO_AES_BLOCK_SIZE);
    int i;
    for (i = 0; i < blocks_num; i++)
    {

        // log_logw(CRYPTO_TAG, "block: %d", i);

#ifdef CRYPTO_USE_PSA
#endif

#ifdef CRYPTO_USE_ATECC
        err = atecc_aes_decrypt_block(data_to_decrypt + (CRYPTO_AES_BLOCK_SIZE * i), CRYPTO_AES_BLOCK_SIZE, CRYPTO_PLAINTEXT_BUFFER + (CRYPTO_AES_BLOCK_SIZE * i), 0, 0);
        if (err != SW_OK)
        {
            log_loge(CRYPTO_TAG, "atecc failed");
            return SW_ERROR;
        }
#endif
        /* xor for cbc */
        crypto_xor_blocks(CRYPTO_PLAINTEXT_BUFFER + (CRYPTO_AES_BLOCK_SIZE * i), iv, 16);
        /* */

        /* change iv */
        iv = data_to_decrypt + (CRYPTO_AES_BLOCK_SIZE * i);
        /**/

        // sleep_ms(1000);
    }

    if (CRYPTO_PLAINTEXT_BUFFER[data_to_decrypt_len - 1] > 16)
    {
        return SW_ERROR;
    }

    crypto_exec_data->plaintext = CRYPTO_PLAINTEXT_BUFFER;
    crypto_exec_data->padding_size = CRYPTO_PLAINTEXT_BUFFER[data_to_decrypt_len - 1];
    crypto_exec_data->plaintext_len = crypto_exec_data->cipher_len - crypto_exec_data->padding_size;
    crypto_exec_data->out_len = crypto_exec_data->cipher_len - crypto_exec_data->padding_size;
    return SW_OK;
}

int crypto_sha256(uint8_t *data, int data_len, uint8_t *hash, uint16_t hash_len)
{

    if (hash_len != PSA_HASH_LENGTH(PSA_ALG_SHA_256))
    {
        return SW_ERROR;
    }

    size_t hash_length = 0;

    psa_status_t stat = psa_hash_compute(PSA_ALG_SHA_256,
                                         data,
                                         (size_t)data_len,
                                         hash,
                                         (size_t)hash_len,
                                         &hash_length);

    if (stat != PSA_SUCCESS)
    {
        log_loge(CRYPTO_TAG, "hash failed: %d", stat);
        return SW_ERROR;
    }
    return SW_OK;
}

int crypto_random(uint8_t *rand, uint16_t rand_len)
{

    uint8_t rand_block_size = 4;

    uint16_t blocks = rand_len / rand_block_size;
    if (rand_len % rand_block_size != 0)
    {
        blocks += 1;
    }
    int i;

    /* check here from where to take the random data from */
    uint32_t rand_number = get_rand_32();
    /* */

    for (i = 0; i < rand_len; i++)
    {
        if (i % rand_block_size == 0)
        {
            rand_number = get_rand_32();
        }
        rand[i] = (rand_number >> (i % rand_block_size)) % 0xff;
    }

    return SW_OK;
}

int crypto_hmac(crypto_exec_data_t *crypto_exec_data)
{
    int err;
    /* get data hash */
    uint8_t data_hash[32];
    err = crypto_sha256(crypto_exec_data->plaintext, crypto_exec_data->plaintext_len, data_hash, 32);
    if (err != SW_OK)
    {
        return err;
    }
    /* */

    // uint8_t data_hex[256] = {
    //     0,
    // };
    // essential_get_hex_string(data_hash, 32, data_hex, 32 * 2, 1);
    // log_logd("ATECC", "hash: %s", data_hex);

    /* get cipher buffer */
    uint8_t *cipher_buffer = NULL;
    err = crypto_get_cipher_buffer(&cipher_buffer);
    if (err != SW_OK)
    {
        return err;
    }
    /**/

    /* get sign */

#ifdef CRYPTO_USE_PSA
#endif

#ifdef CRYPTO_USE_ATECC
    err = atecc_hmac(data_hash, 32, cipher_buffer, 32, 0, 0);
    if (err != SW_OK)
    {
        return err;
    }
/**/
#endif

    crypto_exec_data->cipher = cipher_buffer;
    crypto_exec_data->out_len = 32;
    crypto_exec_data->cipher_len = 32;
}

int crypto_ecdsa(crypto_exec_data_t *crypto_exec_data)
{
    int err;
    /* get data hash */
    uint8_t data_hash[32];
    err = crypto_sha256(crypto_exec_data->plaintext, crypto_exec_data->plaintext_len, data_hash, 32);
    if (err != SW_OK)
    {
        return err;
    }
    /* */

    /* get cipher buffer */
    uint8_t *cipher_buffer = NULL;
    err = crypto_get_cipher_buffer(&cipher_buffer);
    if (err != SW_OK)
    {
        return err;
    }
    /**/

#ifdef CRYPTO_USE_PSA
#endif

#ifdef CRYPTO_USE_ATECC
    err = atecc_perform_ecdsa(data_hash, 32, cipher_buffer, 64);
    if (err != SW_OK)
    {
        return err;
    }
/**/
#endif

    crypto_exec_data->cipher = cipher_buffer;
    crypto_exec_data->out_len = 64;
    crypto_exec_data->cipher_len = 64;

    return SW_OK;
}

int crypto_verify_sign_from_hash(uint8_t *hash_to_verify, int hash_to_verify_len, uint8_t *signature, int signature_len)
{

    psa_status_t status = PSA_SUCCESS;

    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    // Set the key type to ECC public key

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY | PSA_KEY_USAGE_VERIFY_HASH); // Typically, you verify with a public key
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));                     // For example, ECDSA with SHA-256
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));     // Example for NIST P-256 curve
    psa_set_key_bits(&key_attributes, 256);


    status = mbedtls_psa_ecdsa_verify_hash(&key_attributes, PUBLIC_KEY_BYTES, sizeof PUBLIC_KEY_BYTES, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash_to_verify,
                                           hash_to_verify_len, signature, signature_len);

    psa_reset_key_attributes(&key_attributes);
    

    if (status != PSA_SUCCESS)
    {
        log_loge(BOOTLOADER_TAG, "sign verify failed %d", status);
        return SW_ERROR;
    }

    log_logi(BOOTLOADER_TAG, "signature is good!");

    return SW_OK;
}

int crypto_sign_hash(uint8_t *hash_to_sign, int hash_to_sign_length, uint8_t *signature, int signature_length, size_t *signature_written_size, uint8_t *ecc_private_key, int ecc_private_key_length)
{

    psa_status_t status = PSA_SUCCESS;

    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

    // Set the key type to ECC public key

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY | PSA_KEY_USAGE_VERIFY_HASH); // Typically, you verify with a public key
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));                                          // For example, ECDSA with SHA-256
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));                            // Example for NIST P-256 curve
    psa_set_key_bits(&key_attributes, 256);

    status = mbedtls_psa_ecdsa_sign_hash(&key_attributes, ecc_private_key, ecc_private_key_length, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash_to_sign, hash_to_sign_length, signature, signature_length, signature_written_size);

    if (status != PSA_SUCCESS)
    {
        log_loge(BOOTLOADER_TAG, "sign failed %d", status);
        return SW_ERROR;
    }

    return SW_OK;
}
