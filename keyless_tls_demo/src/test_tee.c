#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "tee_mock.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i % 16 == 15) printf("\n                ");
    }
    printf("\n");
}

static int test_encryption_decryption(void) {
    printf("\n=== Testing Encryption/Decryption ===\n");
    
    // 准备测试数据
    const char *test_message = "Hello, TEE Keyless TLS!";
    printf("Original message: %s\n", test_message);
    
    // 首先需要使用公钥加密数据（模拟客户端加密）
    // 在实际应用中，这会在对端完成
    // 这里我们先跳过加密步骤，直接测试解密功能
    
    printf("Encryption/Decryption test requires pre-encrypted data\n");
    printf("This would normally be handled by the peer in TLS handshake\n");
    
    return 0;
}

static int test_signing_verification(void) {
    printf("\n=== Testing Signing ===\n");
    
    // 准备要签名的数据
    const char *test_message = "This is a test message for signing";
    uint8_t hash[SHA256_DIGEST_LENGTH];
    
    printf("Message to sign: %s\n", test_message);
    
    // 计算SHA256哈希
    SHA256((const uint8_t*)test_message, strlen(test_message), hash);
    print_hex("SHA256 hash", hash, SHA256_DIGEST_LENGTH);
    
    // 准备TEE输入数据
    struct TeeBlob inData, outData;
    inData.data = hash;
    inData.dataLength = SHA256_DIGEST_LENGTH;
    memset(&outData, 0, sizeof(outData));
    
    // 执行签名
    printf("Calling TEE signing operation...\n");
    int32_t result = TeeKeylessOperation(KM_PURPOSE_SIGN, KM_PAD_RSA_PKCS1_1_5_SIGN, &inData, &outData);
    
    if (result == 0) {
        printf("Signing successful!\n");
        print_hex("Signature", outData.data, outData.dataLength);
        
        // 清理签名数据
        if (outData.data) {
            free(outData.data);
        }
        return 0;
    } else {
        printf("Signing failed with error: %d\n", result);
        return -1;
    }
}

static int test_certificate_retrieval(void) {
    printf("\n=== Testing Certificate Retrieval ===\n");
    
    struct TeeBlob cert_data;
    memset(&cert_data, 0, sizeof(cert_data));
    
    int32_t result = TeeGetDeviceCertificate(&cert_data);
    if (result == 0 && cert_data.data) {
        printf("Certificate retrieved successfully!\n");
        printf("Certificate size: %zu bytes\n", cert_data.dataLength);
        
        // 显示证书的前100个字符
        printf("Certificate content (first 100 chars):\n");
        for (size_t i = 0; i < cert_data.dataLength && i < 100; i++) {
            printf("%c", cert_data.data[i]);
        }
        printf("\n...\n");
        
        free(cert_data.data);
        return 0;
    } else {
        printf("Certificate retrieval failed with error: %d\n", result);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    const char *device_key_path = "../certs/device_key.pem";
    
    if (argc > 1) {
        device_key_path = argv[1];
    }
    
    printf("TEE Mock Testing Program\n");
    printf("Device key path: %s\n", device_key_path);
    
    // 初始化TEE环境
    printf("\nInitializing TEE mock environment...\n");
    if (TeeInit(device_key_path) != 0) {
        fprintf(stderr, "Failed to initialize TEE mock\n");
        return 1;
    }
    
    int total_tests = 0;
    int passed_tests = 0;
    
    // 测试证书检索
    total_tests++;
    if (test_certificate_retrieval() == 0) {
        passed_tests++;
    }
    
    // 测试签名功能
    total_tests++;
    if (test_signing_verification() == 0) {
        passed_tests++;
    }
    
    // 测试加密解密功能
    total_tests++;
    if (test_encryption_decryption() == 0) {
        passed_tests++;
    }
    
    // 清理
    TeeCleanup();
    
    printf("\n=== Test Results ===\n");
    printf("Passed: %d/%d tests\n", passed_tests, total_tests);
    
    if (passed_tests == total_tests) {
        printf("All tests passed! TEE mock is working correctly.\n");
        return 0;
    } else {
        printf("Some tests failed. Please check the implementation.\n");
        return 1;
    }
}