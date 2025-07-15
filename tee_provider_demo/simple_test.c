#include "tee_provider.h"

/* 简单的Provider测试程序 */
int main() {
    printf("=== 简单的TEE Provider测试 ===\n");
    
    /* 创建库上下文 */
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("ERROR: Failed to create library context\n");
        return 1;
    }
    
    /* 尝试加载TEE Provider */
    if (!OSSL_PROVIDER_add_builtin(libctx, "tee-provider", tee_provider_init)) {
        printf("ERROR: Failed to add builtin TEE provider\n");
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(libctx, "tee-provider");
    if (!prov) {
        printf("ERROR: Failed to load TEE provider\n");
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    printf("SUCCESS: TEE Provider loaded successfully\n");
    
    /* 验证Provider是否可用 */
    if (OSSL_PROVIDER_available(libctx, "tee-provider")) {
        printf("SUCCESS: TEE Provider is available\n");
    } else {
        printf("ERROR: TEE Provider is not available\n");
    }
    
    /* 测试密钥加载 */
    TEE_KEY *key = NULL;
    if (tee_load_private_key_from_file("certs/device_key.pem", &key)) {
        printf("SUCCESS: Private key loaded into TEE\n");
        printf("Key type: %d, Key size: %d bits\n", key->key_type, key->key_size);
        tee_key_free(key);
    } else {
        printf("ERROR: Failed to load private key\n");
    }
    
    /* 清理 */
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    
    printf("=== 测试完成 ===\n");
    return 0;
}