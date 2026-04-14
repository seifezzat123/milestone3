#ifndef SECURITY_H
#define SECURITY_H

#include <openssl/aes.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

unsigned char aes_key[AES_KEY_SIZE] = "1234567890abcdef";

int pad_length(int len) {
    return ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
}

int aes_encrypt(char *data, int len) {
    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);

    int padded_len = pad_length(len);
    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_encrypt((unsigned char*)data + i, (unsigned char*)data + i, &enc_key);
    }
    return padded_len;
}

void aes_decrypt(char *data, int len) {
    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, 128, &dec_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_decrypt((unsigned char*)data + i, (unsigned char*)data + i, &dec_key);
    }
}

#endif
