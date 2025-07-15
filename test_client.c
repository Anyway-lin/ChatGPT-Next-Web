/*
 * TEE Provider 测试客户端
 * 演示如何在C代码中使用TEE Provider进行TLS连接
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

/* 初始化OpenSSL并加载providers */
static int init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /* 加载TEE Provider */
    OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(NULL, "tee");
    if (!tee_prov) {
        fprintf(stderr, "Failed to load TEE provider\n");
        return 0;
    }
    
    /* 加载Default Provider */
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        fprintf(stderr, "Failed to load default provider\n");
        OSSL_PROVIDER_unload(tee_prov);
        return 0;
    }
    
    printf("✓ OpenSSL初始化完成，TEE Provider已加载\n");
    return 1;
}

/* 加载TEE密钥 */
static EVP_PKEY *load_tee_key(const char *key_uri) {
    BIO *bio;
    EVP_PKEY *pkey = NULL;
    
    printf("正在加载TEE密钥: %s\n", key_uri);
    
    /* 创建内存BIO */
    bio = BIO_new_mem_buf(key_uri, -1);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return NULL;
    }
    
    /* 尝试从TEE Provider加载密钥 */
    pkey = d2i_PrivateKey_bio(bio, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        fprintf(stderr, "Failed to load TEE key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    printf("✓ TEE密钥加载成功\n");
    return pkey;
}

/* 加载证书 */
static X509 *load_certificate(const char *cert_file) {
    BIO *bio;
    X509 *cert = NULL;
    
    printf("正在加载证书: %s\n", cert_file);
    
    bio = BIO_new_file(cert_file, "r");
    if (!bio) {
        fprintf(stderr, "Failed to open certificate file: %s\n", cert_file);
        return NULL;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert) {
        fprintf(stderr, "Failed to load certificate\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    printf("✓ 证书加载成功\n");
    return cert;
}

/* 测试签名功能 */
static int test_signing(EVP_PKEY *pkey) {
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *signature = NULL;
    size_t sig_len;
    const char *data = "Hello from TEE Provider!";
    int ret = 0;
    
    printf("\n=== 测试TEE签名功能 ===\n");
    
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create signing context\n");
        goto end;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        fprintf(stderr, "Failed to init signing\n");
        goto end;
    }
    
    /* 获取签名长度 */
    if (EVP_PKEY_sign(ctx, NULL, &sig_len, (unsigned char*)data, strlen(data)) <= 0) {
        fprintf(stderr, "Failed to get signature length\n");
        goto end;
    }
    
    signature = malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Failed to allocate signature buffer\n");
        goto end;
    }
    
    /* 执行签名 */
    if (EVP_PKEY_sign(ctx, signature, &sig_len, (unsigned char*)data, strlen(data)) <= 0) {
        fprintf(stderr, "Failed to sign data\n");
        goto end;
    }
    
    printf("✓ 签名成功，签名长度: %zu bytes\n", sig_len);
    
    /* 显示签名数据 (前16字节) */
    printf("签名数据 (前16字节): ");
    for (int i = 0; i < (sig_len > 16 ? 16 : sig_len); i++) {
        printf("%02x", signature[i]);
    }
    printf("...\n");
    
    ret = 1;
    
end:
    EVP_PKEY_CTX_free(ctx);
    free(signature);
    return ret;
}

/* 测试TLS连接 */
static int test_tls_connection(EVP_PKEY *pkey, X509 *cert, const char *hostname, int port) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    char connect_str[256];
    int ret = 0;
    
    printf("\n=== 测试TLS连接 ===\n");
    printf("连接目标: %s:%d\n", hostname, port);
    
    /* 创建SSL上下文 */
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        goto end;
    }
    
    /* 设置客户端证书和私钥 */
    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        fprintf(stderr, "Failed to set client certificate\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        fprintf(stderr, "Failed to set private key\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    /* 验证私钥和证书匹配 */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        goto end;
    }
    
    printf("✓ SSL上下文配置完成\n");
    
    /* 创建连接 */
    snprintf(connect_str, sizeof(connect_str), "%s:%d", hostname, port);
    bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        fprintf(stderr, "Failed to create SSL BIO\n");
        goto end;
    }
    
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, connect_str);
    
    /* 尝试连接 */
    printf("正在连接 %s...\n", connect_str);
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Failed to connect\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    /* 验证SSL握手 */
    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Failed SSL handshake\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    printf("✓ TLS连接建立成功\n");
    
    /* 获取连接信息 */
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert) {
        char *subj = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);
        printf("服务器证书主题: %s\n", subj);
        OPENSSL_free(subj);
        X509_free(peer_cert);
    }
    
    printf("SSL版本: %s\n", SSL_get_version(ssl));
    printf("加密套件: %s\n", SSL_get_cipher(ssl));
    
    ret = 1;
    
end:
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return ret;
}

int main(int argc, char *argv[]) {
    EVP_PKEY *tee_key = NULL;
    X509 *cert = NULL;
    const char *cert_file = "tee_certificate.pem";
    const char *tee_key_uri = "tee:device_rsa";
    int ret = 1;
    
    printf("========================================\n");
    printf("TEE Provider 测试客户端\n");
    printf("========================================\n");
    
    /* 初始化OpenSSL */
    if (!init_openssl()) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }
    
    /* 加载TEE密钥 */
    tee_key = load_tee_key(tee_key_uri);
    if (!tee_key) {
        fprintf(stderr, "Failed to load TEE key\n");
        goto cleanup;
    }
    
    /* 加载证书 */
    cert = load_certificate(cert_file);
    if (!cert) {
        fprintf(stderr, "Failed to load certificate\n");
        goto cleanup;
    }
    
    /* 测试签名功能 */
    if (!test_signing(tee_key)) {
        fprintf(stderr, "Signing test failed\n");
        goto cleanup;
    }
    
    /* 测试TLS连接 (可选) */
    if (argc > 1 && strcmp(argv[1], "--tls-test") == 0) {
        const char *hostname = argc > 2 ? argv[2] : "httpbin.org";
        int port = argc > 3 ? atoi(argv[3]) : 443;
        
        if (!test_tls_connection(tee_key, cert, hostname, port)) {
            fprintf(stderr, "TLS connection test failed\n");
            goto cleanup;
        }
    }
    
    printf("\n========================================\n");
    printf("✓ 所有测试完成！\n");
    printf("========================================\n");
    
    ret = 0;
    
cleanup:
    EVP_PKEY_free(tee_key);
    X509_free(cert);
    
    /* 清理OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
    
    return ret;
}

/* 编译命令示例:
 * gcc -o test_client test_client.c -lssl -lcrypto
 * 
 * 使用方法:
 * ./test_client                    # 基本测试
 * ./test_client --tls-test         # 包含TLS测试
 * ./test_client --tls-test google.com 443  # 自定义服务器
 */