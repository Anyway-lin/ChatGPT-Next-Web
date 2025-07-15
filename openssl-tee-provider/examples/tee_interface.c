#include "../src/tee_provider.h"

/* 模拟的TEE密钥存储 */
typedef struct {
    uint32_t key_id;
    tee_key_type_t key_type;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    unsigned char aes_key[32];  /* AES-256密钥 */
    size_t aes_key_len;
    char label[64];
} tee_mock_key_t;

/* 模拟密钥存储数组 */
static tee_mock_key_t mock_keys[10];
static int mock_keys_initialized = 0;

/* 初始化模拟密钥 */
static int tee_mock_init_keys(void) {
    if (mock_keys_initialized) {
        return 1;
    }
    
    memset(mock_keys, 0, sizeof(mock_keys));
    
    /* 生成RSA密钥对 (key_id = 1) */
    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (rsa_ctx) {
        if (EVP_PKEY_keygen_init(rsa_ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 2048) > 0) {
            
            EVP_PKEY *rsa_key = NULL;
            if (EVP_PKEY_keygen(rsa_ctx, &rsa_key) > 0) {
                mock_keys[0].key_id = 1;
                mock_keys[0].key_type = TEE_KEY_TYPE_RSA;
                mock_keys[0].private_key = rsa_key;
                mock_keys[0].public_key = rsa_key;
                EVP_PKEY_up_ref(rsa_key);  /* 增加引用计数 */
                strcpy(mock_keys[0].label, "device_key");
                printf("[TEE Mock] Generated RSA key pair (ID: 1)\n");
            }
        }
        EVP_PKEY_CTX_free(rsa_ctx);
    }
    
    /* 生成EC密钥对 (key_id = 2) */
    EVP_PKEY_CTX *ec_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ec_ctx) {
        if (EVP_PKEY_keygen_init(ec_ctx) > 0 &&
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_ctx, NID_X9_62_prime256v1) > 0) {
            
            EVP_PKEY *ec_key = NULL;
            if (EVP_PKEY_keygen(ec_ctx, &ec_key) > 0) {
                mock_keys[1].key_id = 2;
                mock_keys[1].key_type = TEE_KEY_TYPE_EC;
                mock_keys[1].private_key = ec_key;
                mock_keys[1].public_key = ec_key;
                EVP_PKEY_up_ref(ec_key);
                strcpy(mock_keys[1].label, "ec_key");
                printf("[TEE Mock] Generated EC key pair (ID: 2)\n");
            }
        }
        EVP_PKEY_CTX_free(ec_ctx);
    }
    
    /* 生成AES密钥 (key_id = 3) */
    mock_keys[2].key_id = 3;
    mock_keys[2].key_type = TEE_KEY_TYPE_AES;
    mock_keys[2].aes_key_len = 32;
    if (RAND_bytes(mock_keys[2].aes_key, 32) == 1) {
        strcpy(mock_keys[2].label, "aes_key");
        printf("[TEE Mock] Generated AES-256 key (ID: 3)\n");
    }
    
    mock_keys_initialized = 1;
    return 1;
}

/* 查找模拟密钥 */
static tee_mock_key_t *tee_mock_find_key(uint32_t key_id) {
    if (!mock_keys_initialized) {
        tee_mock_init_keys();
    }
    
    for (int i = 0; i < 10; i++) {
        if (mock_keys[i].key_id == key_id) {
            return &mock_keys[i];
        }
    }
    return NULL;
}

/* TEE模拟签名函数 */
int tee_mock_sign(const unsigned char *data, size_t data_len,
                 unsigned char *sig, size_t *sig_len,
                 uint32_t key_id, tee_algorithm_t alg) {
    
    tee_mock_key_t *key = tee_mock_find_key(key_id);
    if (!key || !key->private_key) {
        printf("[TEE Mock] Key not found: ID %u\n", key_id);
        return 0;
    }
    
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    const EVP_MD *md = NULL;
    int ret = 0;
    
    /* 选择摘要算法 */
    switch (alg) {
    case TEE_ALG_RSA_PKCS1_V1_5:
    case TEE_ALG_RSA_PSS:
        md = EVP_sha256();
        break;
    case TEE_ALG_ECDSA_P256:
        md = EVP_sha256();
        break;
    case TEE_ALG_ECDSA_P384:
        md = EVP_sha384();
        break;
    default:
        printf("[TEE Mock] Unsupported signature algorithm: %d\n", alg);
        return 0;
    }
    
    /* 创建签名上下文 */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }
    
    /* 初始化签名 */
    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, key->private_key) != 1) {
        printf("[TEE Mock] Failed to initialize signature\n");
        goto cleanup;
    }
    
    /* 设置RSA填充模式 */
    if (key->key_type == TEE_KEY_TYPE_RSA) {
        if (alg == TEE_ALG_RSA_PSS) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
                printf("[TEE Mock] Failed to set PSS padding\n");
                goto cleanup;
            }
        } else {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) != 1) {
                printf("[TEE Mock] Failed to set PKCS1 padding\n");
                goto cleanup;
            }
        }
    }
    
    /* 计算签名 */
    if (EVP_DigestSign(md_ctx, sig, sig_len, data, data_len) != 1) {
        printf("[TEE Mock] Failed to compute signature\n");
        goto cleanup;
    }
    
    printf("[TEE Mock] Signature computed successfully (key_id: %u, sig_len: %zu)\n", 
           key_id, *sig_len);
    ret = 1;
    
cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret;
}

/* TEE模拟验签函数 */
int tee_mock_verify(const unsigned char *data, size_t data_len,
                   const unsigned char *sig, size_t sig_len,
                   uint32_t key_id, tee_algorithm_t alg) {
    
    tee_mock_key_t *key = tee_mock_find_key(key_id);
    if (!key || !key->public_key) {
        printf("[TEE Mock] Key not found: ID %u\n", key_id);
        return 0;
    }
    
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    const EVP_MD *md = NULL;
    int ret = 0;
    
    /* 选择摘要算法 */
    switch (alg) {
    case TEE_ALG_RSA_PKCS1_V1_5:
    case TEE_ALG_RSA_PSS:
        md = EVP_sha256();
        break;
    case TEE_ALG_ECDSA_P256:
        md = EVP_sha256();
        break;
    case TEE_ALG_ECDSA_P384:
        md = EVP_sha384();
        break;
    default:
        printf("[TEE Mock] Unsupported verification algorithm: %d\n", alg);
        return 0;
    }
    
    /* 创建验签上下文 */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        goto cleanup;
    }
    
    /* 初始化验签 */
    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, md, NULL, key->public_key) != 1) {
        printf("[TEE Mock] Failed to initialize verification\n");
        goto cleanup;
    }
    
    /* 设置RSA填充模式 */
    if (key->key_type == TEE_KEY_TYPE_RSA) {
        if (alg == TEE_ALG_RSA_PSS) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
                printf("[TEE Mock] Failed to set PSS padding\n");
                goto cleanup;
            }
        } else {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) != 1) {
                printf("[TEE Mock] Failed to set PKCS1 padding\n");
                goto cleanup;
            }
        }
    }
    
    /* 验证签名 */
    if (EVP_DigestVerify(md_ctx, sig, sig_len, data, data_len) == 1) {
        printf("[TEE Mock] Signature verification successful (key_id: %u)\n", key_id);
        ret = 1;
    } else {
        printf("[TEE Mock] Signature verification failed (key_id: %u)\n", key_id);
    }
    
cleanup:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    return ret;
}

/* TEE模拟加密函数 */
int tee_mock_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, size_t *ciphertext_len,
                    uint32_t key_id, tee_algorithm_t alg,
                    const unsigned char *iv, size_t iv_len) {
    
    tee_mock_key_t *key = tee_mock_find_key(key_id);
    if (!key) {
        printf("[TEE Mock] Key not found: ID %u\n", key_id);
        return 0;
    }
    
    if (alg == TEE_ALG_AES_GCM || alg == TEE_ALG_AES_CBC) {
        if (key->key_type != TEE_KEY_TYPE_AES) {
            printf("[TEE Mock] Invalid key type for AES encryption\n");
            return 0;
        }
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return 0;
        }
        
        const EVP_CIPHER *cipher = (alg == TEE_ALG_AES_GCM) ? 
                                  EVP_aes_256_gcm() : EVP_aes_256_cbc();
        
        int len, ret = 0;
        
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, key->aes_key, iv) == 1) {
            if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) == 1) {
                *ciphertext_len = len;
                
                if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) == 1) {
                    *ciphertext_len += len;
                    ret = 1;
                    printf("[TEE Mock] AES encryption successful (key_id: %u, len: %zu)\n", 
                           key_id, *ciphertext_len);
                }
            }
        }
        
        EVP_CIPHER_CTX_free(ctx);
        return ret;
    }
    
    printf("[TEE Mock] Unsupported encryption algorithm: %d\n", alg);
    return 0;
}

/* TEE模拟解密函数 */
int tee_mock_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, size_t *plaintext_len,
                    uint32_t key_id, tee_algorithm_t alg,
                    const unsigned char *iv, size_t iv_len) {
    
    tee_mock_key_t *key = tee_mock_find_key(key_id);
    if (!key) {
        printf("[TEE Mock] Key not found: ID %u\n", key_id);
        return 0;
    }
    
    if (alg == TEE_ALG_AES_GCM || alg == TEE_ALG_AES_CBC) {
        if (key->key_type != TEE_KEY_TYPE_AES) {
            printf("[TEE Mock] Invalid key type for AES decryption\n");
            return 0;
        }
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return 0;
        }
        
        const EVP_CIPHER *cipher = (alg == TEE_ALG_AES_GCM) ? 
                                  EVP_aes_256_gcm() : EVP_aes_256_cbc();
        
        int len, ret = 0;
        
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, key->aes_key, iv) == 1) {
            if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) == 1) {
                *plaintext_len = len;
                
                if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) == 1) {
                    *plaintext_len += len;
                    ret = 1;
                    printf("[TEE Mock] AES decryption successful (key_id: %u, len: %zu)\n", 
                           key_id, *plaintext_len);
                }
            }
        }
        
        EVP_CIPHER_CTX_free(ctx);
        return ret;
    }
    
    printf("[TEE Mock] Unsupported decryption algorithm: %d\n", alg);
    return 0;
}

/* 导出公钥到证书文件 - 用于生成测试证书 */
int tee_mock_export_public_key_to_cert(uint32_t key_id, const char *cert_file) {
    tee_mock_key_t *key = tee_mock_find_key(key_id);
    if (!key || !key->public_key) {
        printf("[TEE Mock] Key not found: ID %u\n", key_id);
        return 0;
    }
    
    X509 *cert = X509_new();
    if (!cert) {
        return 0;
    }
    
    /* 设置证书版本 */
    X509_set_version(cert, 2);
    
    /* 设置序列号 */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), key_id);
    
    /* 设置有效期 */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600); /* 1年 */
    
    /* 设置公钥 */
    X509_set_pubkey(cert, key->public_key);
    
    /* 设置主题名称 */
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"TEE Provider", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)key->label, -1, -1, 0);
    
    /* 设置颁发者名称 */
    X509_set_issuer_name(cert, name);
    
    /* 自签名 */
    if (X509_sign(cert, key->private_key, EVP_sha256()) == 0) {
        X509_free(cert);
        return 0;
    }
    
    /* 写入文件 */
    FILE *fp = fopen(cert_file, "w");
    if (fp) {
        PEM_write_X509(fp, cert);
        fclose(fp);
        printf("[TEE Mock] Certificate exported to %s\n", cert_file);
    }
    
    X509_free(cert);
    return 1;
}

/* 清理模拟密钥 */
void tee_mock_cleanup(void) {
    if (!mock_keys_initialized) {
        return;
    }
    
    for (int i = 0; i < 10; i++) {
        if (mock_keys[i].private_key) {
            EVP_PKEY_free(mock_keys[i].private_key);
        }
        if (mock_keys[i].public_key && mock_keys[i].public_key != mock_keys[i].private_key) {
            EVP_PKEY_free(mock_keys[i].public_key);
        }
    }
    
    memset(mock_keys, 0, sizeof(mock_keys));
    mock_keys_initialized = 0;
    printf("[TEE Mock] Cleanup completed\n");
}