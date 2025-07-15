#include "tee_mock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// 全局变量存储私钥和证书
static EVP_PKEY *g_device_key = NULL;
static uint8_t *g_device_cert_data = NULL;
static size_t g_device_cert_size = 0;

// 错误处理函数
static void print_openssl_errors(const char *func_name) {
    unsigned long err;
    char err_buf[256];
    fprintf(stderr, "OpenSSL error in %s:\n", func_name);
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "  %s\n", err_buf);
    }
}

int32_t TeeInit(const char *device_key_path) {
    FILE *key_file = NULL;
    FILE *cert_file = NULL;
    long cert_size;
    
    // 清理之前的状态
    TeeCleanup();
    
    // 加载设备私钥
    key_file = fopen(device_key_path, "r");
    if (!key_file) {
        fprintf(stderr, "Failed to open device key file: %s\n", device_key_path);
        return -1;
    }
    
    g_device_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!g_device_key) {
        fprintf(stderr, "Failed to load device private key\n");
        print_openssl_errors("TeeInit");
        return -1;
    }
    
    // 加载设备证书（用于后续证书链构建）
    char cert_path[512];
    strncpy(cert_path, device_key_path, sizeof(cert_path) - 1);
    cert_path[sizeof(cert_path) - 1] = '\0';
    
    // 将key.pem替换为cert.pem
    char *ext = strstr(cert_path, "_key.pem");
    if (ext) {
        strcpy(ext, "_cert.pem");
    } else {
        // 如果没找到_key.pem，尝试替换.pem
        ext = strstr(cert_path, ".pem");
        if (ext) {
            strcpy(ext, "_cert.pem");
        }
    }
    
    cert_file = fopen(cert_path, "r");
    if (cert_file) {
        // 获取证书文件大小
        fseek(cert_file, 0, SEEK_END);
        cert_size = ftell(cert_file);
        fseek(cert_file, 0, SEEK_SET);
        
        // 分配内存并读取证书
        g_device_cert_data = malloc(cert_size);
        if (g_device_cert_data) {
            g_device_cert_size = fread(g_device_cert_data, 1, cert_size, cert_file);
        }
        fclose(cert_file);
    }
    
    printf("TEE Mock initialized successfully\n");
    return 0;
}

void TeeCleanup(void) {
    if (g_device_key) {
        EVP_PKEY_free(g_device_key);
        g_device_key = NULL;
    }
    
    if (g_device_cert_data) {
        free(g_device_cert_data);
        g_device_cert_data = NULL;
        g_device_cert_size = 0;
    }
}

int32_t TeeGetDeviceCertificate(struct TeeBlob *cert_data) {
    if (!cert_data || !g_device_cert_data) {
        return -1;
    }
    
    cert_data->data = malloc(g_device_cert_size);
    if (!cert_data->data) {
        return -1;
    }
    
    memcpy(cert_data->data, g_device_cert_data, g_device_cert_size);
    cert_data->dataLength = g_device_cert_size;
    
    return 0;
}

int32_t TeeKeylessOperation(enum TeeKeyPurpose purpose, uint32_t padType, 
                           struct TeeBlob *inData, struct TeeBlob *outData) {
    if (!g_device_key || !inData || !outData) {
        fprintf(stderr, "TEE not initialized or invalid parameters\n");
        return -1;
    }
    
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len = 0;
    int ret = -1;
    
    switch (purpose) {
        case KM_PURPOSE_DECRYPT: {
            // RSA解密操作
            ctx = EVP_PKEY_CTX_new(g_device_key, NULL);
            if (!ctx) {
                print_openssl_errors("EVP_PKEY_CTX_new");
                return -1;
            }
            
            if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                print_openssl_errors("EVP_PKEY_decrypt_init");
                goto cleanup;
            }
            
            // 设置填充模式
            int padding;
            switch (padType) {
                case KM_PAD_RSA_OAEP:
                    padding = RSA_PKCS1_OAEP_PADDING;
                    break;
                case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
                    padding = RSA_PKCS1_PADDING;
                    break;
                case KM_PAD_NONE:
                    padding = RSA_NO_PADDING;
                    break;
                default:
                    fprintf(stderr, "Unsupported padding type for decryption: %u\n", padType);
                    goto cleanup;
            }
            
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
                print_openssl_errors("EVP_PKEY_CTX_set_rsa_padding");
                goto cleanup;
            }
            
            // 获取输出长度
            if (EVP_PKEY_decrypt(ctx, NULL, &out_len, inData->data, inData->dataLength) <= 0) {
                print_openssl_errors("EVP_PKEY_decrypt (length)");
                goto cleanup;
            }
            
            // 分配输出缓冲区
            outData->data = malloc(out_len);
            if (!outData->data) {
                fprintf(stderr, "Memory allocation failed\n");
                goto cleanup;
            }
            
            // 执行解密
            if (EVP_PKEY_decrypt(ctx, outData->data, &out_len, inData->data, inData->dataLength) <= 0) {
                print_openssl_errors("EVP_PKEY_decrypt");
                free(outData->data);
                outData->data = NULL;
                goto cleanup;
            }
            
            outData->dataLength = out_len;
            ret = 0;
            break;
        }
        
        case KM_PURPOSE_SIGN: {
            // RSA签名操作
            ctx = EVP_PKEY_CTX_new(g_device_key, NULL);
            if (!ctx) {
                print_openssl_errors("EVP_PKEY_CTX_new");
                return -1;
            }
            
            if (EVP_PKEY_sign_init(ctx) <= 0) {
                print_openssl_errors("EVP_PKEY_sign_init");
                goto cleanup;
            }
            
            // 设置填充模式
            int padding;
            switch (padType) {
                case KM_PAD_RSA_PKCS1_1_5_SIGN:
                    padding = RSA_PKCS1_PADDING;
                    break;
                case KM_PAD_RSA_PSS:
                    padding = RSA_PKCS1_PSS_PADDING;
                    break;
                case KM_PAD_NONE:
                    padding = RSA_NO_PADDING;
                    break;
                default:
                    fprintf(stderr, "Unsupported padding type for signing: %u\n", padType);
                    goto cleanup;
            }
            
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
                print_openssl_errors("EVP_PKEY_CTX_set_rsa_padding");
                goto cleanup;
            }
            
            // 设置签名算法为SHA256
            if (padding != RSA_NO_PADDING) {
                if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
                    print_openssl_errors("EVP_PKEY_CTX_set_signature_md");
                    goto cleanup;
                }
            }
            
            // 获取输出长度
            if (EVP_PKEY_sign(ctx, NULL, &out_len, inData->data, inData->dataLength) <= 0) {
                print_openssl_errors("EVP_PKEY_sign (length)");
                goto cleanup;
            }
            
            // 分配输出缓冲区
            outData->data = malloc(out_len);
            if (!outData->data) {
                fprintf(stderr, "Memory allocation failed\n");
                goto cleanup;
            }
            
            // 执行签名
            if (EVP_PKEY_sign(ctx, outData->data, &out_len, inData->data, inData->dataLength) <= 0) {
                print_openssl_errors("EVP_PKEY_sign");
                free(outData->data);
                outData->data = NULL;
                goto cleanup;
            }
            
            outData->dataLength = out_len;
            ret = 0;
            break;
        }
        
        default:
            fprintf(stderr, "Unsupported TEE operation: %d\n", purpose);
            return -1;
    }
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    
    return ret;
}