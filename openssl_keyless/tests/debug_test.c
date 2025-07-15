#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "tee_sign.h"

static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_ssl_errors(void) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "SSL Error: %s\n", err_buf);
    }
}

int main(void) {
    printf("=== TEE Signing Debug Test ===\n");
    
    // 初始化TEE
    if (tee_init() != TEE_SUCCESS) {
        printf("Failed to initialize TEE\n");
        return 1;
    }
    
    // 创建TEE密钥句柄
    tee_key_handle_t *handle = NULL;
    tee_result_t result = tee_create_key_handle(1, TEE_ALG_RSA_PKCS1_SHA256, 2048, &handle);
    if (result != TEE_SUCCESS) {
        printf("Failed to create TEE key handle: %d\n", result);
        tee_cleanup();
        return 1;
    }
    
    // 获取公钥
    unsigned char pub_key_der[4096];
    size_t pub_key_len = sizeof(pub_key_der);
    result = tee_get_public_key(handle, pub_key_der, &pub_key_len);
    if (result != TEE_SUCCESS) {
        printf("Failed to get public key: %d\n", result);
        tee_destroy_key_handle(handle);
        tee_cleanup();
        return 1;
    }
    
    printf("Public key length: %zu bytes\n", pub_key_len);
    
    // 解析公钥
    const unsigned char *p = pub_key_der;
    EVP_PKEY *public_key = d2i_PUBKEY(NULL, &p, pub_key_len);
    if (!public_key) {
        printf("Failed to parse public key\n");
        print_ssl_errors();
        tee_destroy_key_handle(handle);
        tee_cleanup();
        return 1;
    }
    
    printf("Public key parsed successfully\n");
    printf("Key type: %d\n", EVP_PKEY_id(public_key));
    printf("Key size: %d bits\n", EVP_PKEY_bits(public_key));
    
    // 测试数据
    const unsigned char test_data[] = "Hello, TEE!";
    size_t test_data_len = strlen((const char*)test_data);
    
    // TEE签名
    unsigned char signature[512];
    size_t signature_len = sizeof(signature);
    result = tee_sign(handle, test_data, test_data_len, signature, &signature_len);
    if (result != TEE_SUCCESS) {
        printf("TEE signing failed: %d\n", result);
        EVP_PKEY_free(public_key);
        tee_destroy_key_handle(handle);
        tee_cleanup();
        return 1;
    }
    
    printf("TEE signature length: %zu bytes\n", signature_len);
    print_hex("Signature", signature, signature_len > 32 ? 32 : signature_len);
    
    // 验证签名
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("Failed to create MD context\n");
        EVP_PKEY_free(public_key);
        tee_destroy_key_handle(handle);
        tee_cleanup();
        return 1;
    }
    
    int verify_result = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, public_key) == 1 &&
        EVP_DigestVerifyUpdate(mdctx, test_data, test_data_len) == 1 &&
        EVP_DigestVerifyFinal(mdctx, signature, signature_len) == 1) {
        verify_result = 1;
        printf("Signature verification: SUCCESS\n");
    } else {
        printf("Signature verification: FAILED\n");
        print_ssl_errors();
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // 清理
    EVP_PKEY_free(public_key);
    tee_destroy_key_handle(handle);
    tee_cleanup();
    
    return verify_result ? 0 : 1;
}