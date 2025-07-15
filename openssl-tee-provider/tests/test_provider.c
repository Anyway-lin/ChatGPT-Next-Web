#include "../src/tee_provider.h"

/* 测试数据 */
static const char *test_data = "Hello, TEE Provider! This is test data for signature and encryption.";
static const unsigned char test_iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

/* 测试结果统计 */
typedef struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
} test_results_t;

static test_results_t test_results = {0, 0, 0};

/* 测试辅助宏 */
#define TEST_START(name) \
    do { \
        printf("\n--- Running Test: %s ---\n", name); \
        test_results.total_tests++; \
    } while(0)

#define TEST_ASSERT(condition, message) \
    do { \
        if (condition) { \
            printf("✓ %s\n", message); \
        } else { \
            printf("✗ %s\n", message); \
            test_results.failed_tests++; \
            return 0; \
        } \
    } while(0)

#define TEST_END() \
    do { \
        test_results.passed_tests++; \
        printf("✓ Test passed\n"); \
        return 1; \
    } while(0)

/* 测试TEE接口初始化 */
int test_tee_init(void) {
    TEST_START("TEE Interface Initialization");
    
    /* 初始化TEE Provider */
    const OSSL_DISPATCH *dispatch_table;
    void *provctx;
    
    int ret = tee_provider_init(NULL, NULL, &dispatch_table, &provctx);
    TEST_ASSERT(ret == 1, "TEE Provider initialization");
    TEST_ASSERT(provctx != NULL, "Provider context creation");
    TEST_ASSERT(dispatch_table != NULL, "Provider dispatch table");
    
    /* 清理 */
    tee_provider_teardown(provctx);
    
    TEST_END();
}

/* 测试RSA签名和验签 */
int test_rsa_signature(void) {
    TEST_START("RSA Signature and Verification");
    
    unsigned char signature[512];
    size_t sig_len = sizeof(signature);
    uint32_t key_id = 1;  /* RSA密钥ID */
    tee_algorithm_t alg = TEE_ALG_RSA_PKCS1_V1_5;
    
    /* 测试签名 */
    int ret = tee_mock_sign((const unsigned char *)test_data, strlen(test_data),
                           signature, &sig_len, key_id, alg);
    TEST_ASSERT(ret == 1, "RSA signature generation");
    TEST_ASSERT(sig_len > 0 && sig_len <= sizeof(signature), "Signature length validation");
    
    printf("Generated signature length: %zu bytes\n", sig_len);
    
    /* 测试验签 */
    ret = tee_mock_verify((const unsigned char *)test_data, strlen(test_data),
                         signature, sig_len, key_id, alg);
    TEST_ASSERT(ret == 1, "RSA signature verification");
    
    /* 测试错误数据验签（应该失败） */
    const char *wrong_data = "Wrong data for verification test";
    ret = tee_mock_verify((const unsigned char *)wrong_data, strlen(wrong_data),
                         signature, sig_len, key_id, alg);
    TEST_ASSERT(ret == 0, "RSA signature verification with wrong data (should fail)");
    
    TEST_END();
}

/* 测试ECDSA签名和验签 */
int test_ecdsa_signature(void) {
    TEST_START("ECDSA Signature and Verification");
    
    unsigned char signature[256];
    size_t sig_len = sizeof(signature);
    uint32_t key_id = 2;  /* EC密钥ID */
    tee_algorithm_t alg = TEE_ALG_ECDSA_P256;
    
    /* 测试签名 */
    int ret = tee_mock_sign((const unsigned char *)test_data, strlen(test_data),
                           signature, &sig_len, key_id, alg);
    TEST_ASSERT(ret == 1, "ECDSA signature generation");
    TEST_ASSERT(sig_len > 0 && sig_len <= sizeof(signature), "Signature length validation");
    
    printf("Generated ECDSA signature length: %zu bytes\n", sig_len);
    
    /* 测试验签 */
    ret = tee_mock_verify((const unsigned char *)test_data, strlen(test_data),
                         signature, sig_len, key_id, alg);
    TEST_ASSERT(ret == 1, "ECDSA signature verification");
    
    TEST_END();
}

/* 测试AES加密和解密 */
int test_aes_encryption(void) {
    TEST_START("AES Encryption and Decryption");
    
    unsigned char ciphertext[1024];
    unsigned char plaintext[1024];
    size_t cipher_len = sizeof(ciphertext);
    size_t plain_len = sizeof(plaintext);
    uint32_t key_id = 3;  /* AES密钥ID */
    tee_algorithm_t alg = TEE_ALG_AES_CBC;
    
    /* 测试加密 */
    int ret = tee_mock_encrypt((const unsigned char *)test_data, strlen(test_data),
                              ciphertext, &cipher_len, key_id, alg,
                              test_iv, sizeof(test_iv));
    TEST_ASSERT(ret == 1, "AES encryption");
    TEST_ASSERT(cipher_len > 0 && cipher_len <= sizeof(ciphertext), "Ciphertext length validation");
    
    printf("Encrypted data length: %zu bytes\n", cipher_len);
    
    /* 测试解密 */
    ret = tee_mock_decrypt(ciphertext, cipher_len,
                          plaintext, &plain_len, key_id, alg,
                          test_iv, sizeof(test_iv));
    TEST_ASSERT(ret == 1, "AES decryption");
    TEST_ASSERT(plain_len == strlen(test_data), "Decrypted data length validation");
    
    /* 验证解密数据正确性 */
    plaintext[plain_len] = '\0';
    ret = (strcmp((const char *)plaintext, test_data) == 0);
    TEST_ASSERT(ret == 1, "Decrypted data integrity");
    
    printf("Decrypted data: %s\n", plaintext);
    
    TEST_END();
}

/* 测试密钥导出 */
int test_key_export(void) {
    TEST_START("Key Export to Certificate");
    
    /* 创建临时证书文件 */
    const char *cert_file = "/tmp/test_device_cert.pem";
    uint32_t key_id = 1;
    
    int ret = tee_mock_export_public_key_to_cert(key_id, cert_file);
    TEST_ASSERT(ret == 1, "Public key export to certificate");
    
    /* 验证证书文件是否创建 */
    FILE *fp = fopen(cert_file, "r");
    TEST_ASSERT(fp != NULL, "Certificate file creation");
    
    if (fp) {
        fclose(fp);
        
        /* 使用OpenSSL验证证书格式 */
        X509 *cert = NULL;
        fp = fopen(cert_file, "r");
        if (fp) {
            cert = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose(fp);
        }
        
        TEST_ASSERT(cert != NULL, "Certificate format validation");
        
        if (cert) {
            /* 验证证书中的公钥 */
            EVP_PKEY *pub_key = X509_get_pubkey(cert);
            TEST_ASSERT(pub_key != NULL, "Public key extraction from certificate");
            
            if (pub_key) {
                int key_type = EVP_PKEY_id(pub_key);
                TEST_ASSERT(key_type == EVP_PKEY_RSA, "Public key type validation");
                EVP_PKEY_free(pub_key);
            }
            
            X509_free(cert);
        }
        
        /* 清理临时文件 */
        unlink(cert_file);
    }
    
    TEST_END();
}

/* 测试错误处理 */
int test_error_handling(void) {
    TEST_START("Error Handling");
    
    unsigned char signature[256];
    size_t sig_len = sizeof(signature);
    
    /* 测试无效密钥ID */
    uint32_t invalid_key_id = 999;
    int ret = tee_mock_sign((const unsigned char *)test_data, strlen(test_data),
                           signature, &sig_len, invalid_key_id, TEE_ALG_RSA_PKCS1_V1_5);
    TEST_ASSERT(ret == 0, "Invalid key ID handling");
    
    /* 测试无效算法 */
    ret = tee_mock_sign((const unsigned char *)test_data, strlen(test_data),
                       signature, &sig_len, 1, (tee_algorithm_t)999);
    TEST_ASSERT(ret == 0, "Invalid algorithm handling");
    
    /* 测试空数据 */
    ret = tee_mock_sign(NULL, 0, signature, &sig_len, 1, TEE_ALG_RSA_PKCS1_V1_5);
    TEST_ASSERT(ret == 0, "NULL data handling");
    
    TEST_END();
}

/* 测试Provider查询功能 */
int test_provider_query(void) {
    TEST_START("Provider Query Functions");
    
    /* 初始化Provider */
    const OSSL_DISPATCH *dispatch_table;
    void *provctx;
    
    int ret = tee_provider_init(NULL, NULL, &dispatch_table, &provctx);
    TEST_ASSERT(ret == 1, "Provider initialization for query test");
    
    /* 测试Provider自检 */
    tee_provider_ctx_t *ctx = (tee_provider_ctx_t *)provctx;
    TEST_ASSERT(ctx != NULL, "Provider context validation");
    TEST_ASSERT(ctx->provider_name != NULL, "Provider name validation");
    TEST_ASSERT(strcmp(ctx->provider_name, TEE_PROVIDER_NAME) == 0, "Provider name correctness");
    
    /* 测试函数指针 */
    TEST_ASSERT(ctx->tee_sign_func != NULL, "TEE sign function pointer");
    TEST_ASSERT(ctx->tee_verify_func != NULL, "TEE verify function pointer");
    TEST_ASSERT(ctx->tee_encrypt_func != NULL, "TEE encrypt function pointer");
    TEST_ASSERT(ctx->tee_decrypt_func != NULL, "TEE decrypt function pointer");
    
    /* 清理 */
    tee_provider_teardown(provctx);
    
    TEST_END();
}

/* 测试性能 */
int test_performance(void) {
    TEST_START("Performance Test");
    
    const int iterations = 100;
    unsigned char signature[512];
    size_t sig_len = sizeof(signature);
    uint32_t key_id = 1;
    tee_algorithm_t alg = TEE_ALG_RSA_PKCS1_V1_5;
    
    clock_t start = clock();
    
    /* 执行多次签名操作 */
    for (int i = 0; i < iterations; i++) {
        sig_len = sizeof(signature);
        int ret = tee_mock_sign((const unsigned char *)test_data, strlen(test_data),
                               signature, &sig_len, key_id, alg);
        if (ret != 1) {
            printf("✗ Signature operation failed at iteration %d\n", i);
            test_results.failed_tests++;
            return 0;
        }
    }
    
    clock_t end = clock();
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    
    printf("Performance: %d RSA signatures in %.2f seconds\n", iterations, cpu_time_used);
    printf("Average time per signature: %.2f ms\n", (cpu_time_used * 1000) / iterations);
    
    TEST_ASSERT(cpu_time_used < 10.0, "Performance within acceptable range");
    
    TEST_END();
}

/* 打印测试摘要 */
void print_test_summary(void) {
    printf("\n" "===" " Test Summary " "===" "\n");
    printf("Total tests:  %d\n", test_results.total_tests);
    printf("Passed tests: %d\n", test_results.passed_tests);
    printf("Failed tests: %d\n", test_results.failed_tests);
    
    if (test_results.failed_tests == 0) {
        printf("🎉 All tests PASSED!\n");
    } else {
        printf("❌ Some tests FAILED!\n");
    }
    
    printf("Success rate: %.1f%%\n", 
           (test_results.passed_tests * 100.0) / test_results.total_tests);
}

/* 主测试函数 */
int main(void) {
    printf("=== TEE Provider Test Suite ===\n");
    printf("Testing OpenSSL 3.0.9 TEE Provider functionality\n");
    
    /* 初始化OpenSSL */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    
    /* 运行测试套件 */
    test_tee_init();
    test_rsa_signature();
    test_ecdsa_signature();
    test_aes_encryption();
    test_key_export();
    test_error_handling();
    test_provider_query();
    test_performance();
    
    /* 打印测试摘要 */
    print_test_summary();
    
    /* 清理OpenSSL */
    tee_mock_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    
    /* 返回状态码 */
    return (test_results.failed_tests == 0) ? 0 : 1;
}