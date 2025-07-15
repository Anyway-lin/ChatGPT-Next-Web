#include "../src/tee_provider.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_PORT 8443
#define SERVER_IP "127.0.0.1"

/* 全局变量 */
static tee_provider_ctx_t *g_tee_ctx = NULL;

/* TEE客户端证书回调函数 */
int tee_client_cert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey) {
    printf("[Client] Certificate callback invoked\n");
    
    if (!g_tee_ctx || !g_tee_ctx->keystore) {
        printf("[Client] TEE context not available\n");
        return 0;
    }
    
    /* 获取设备证书 */
    if (sk_num(g_tee_ctx->keystore) > 0) {
        tee_keystore_entry_t *entry = (tee_keystore_entry_t *)sk_value(g_tee_ctx->keystore, 0);
        if (entry && entry->cert) {
            /* 返回证书 */
            *x509 = entry->cert;
            X509_up_ref(entry->cert);  /* 增加引用计数 */
            
            /* 创建一个虚拟的私钥句柄 */
            /* 注意：这里不提供真实的私钥，签名操作将通过TEE接口完成 */
            EVP_PKEY *pub_key = tee_create_public_key_from_cert(entry->cert);
            if (pub_key) {
                *pkey = pub_key;
                printf("[Client] Certificate and public key provided\n");
                return 1;
            }
        }
    }
    
    printf("[Client] No certificate available\n");
    return 0;
}

/* 自定义签名方法 */
typedef struct {
    const EVP_PKEY_METHOD *orig_method;
    int (*orig_sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                     const unsigned char *tbs, size_t tbslen);
} tee_pkey_method_data_t;

/* TEE签名函数 */
static int tee_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen) {
    printf("[Client] TEE RSA signature requested\n");
    
    if (!g_tee_ctx || !g_tee_ctx->tee_sign_func) {
        printf("[Client] TEE context not available for signing\n");
        return 0;
    }
    
    /* 使用TEE接口进行签名 */
    uint32_t key_id = 1;  /* 设备密钥ID */
    tee_algorithm_t alg = TEE_ALG_RSA_PKCS1_V1_5;
    
    if (g_tee_ctx->tee_sign_func(tbs, tbslen, sig, siglen, key_id, alg) == 1) {
        printf("[Client] TEE signature successful\n");
        return 1;
    }
    
    printf("[Client] TEE signature failed\n");
    return 0;
}

/* 初始化TEE Provider */
int init_tee_provider(void) {
    OSSL_PROVIDER *provider;
    
    /* 加载TEE Provider */
    provider = OSSL_PROVIDER_load(NULL, "./build/libtee_provider.so");
    if (!provider) {
        printf("[Client] Failed to load TEE provider from shared library\n");
        
        /* 尝试直接初始化Provider */
        const OSSL_DISPATCH *dispatch_table;
        void *provctx;
        
        if (tee_provider_init(NULL, NULL, &dispatch_table, &provctx) == 1) {
            g_tee_ctx = (tee_provider_ctx_t *)provctx;
            printf("[Client] TEE provider initialized directly\n");
            return 1;
        } else {
            printf("[Client] Failed to initialize TEE provider\n");
            return 0;
        }
    }
    
    printf("[Client] TEE provider loaded successfully\n");
    return 1;
}

/* 设置SSL上下文 */
SSL_CTX *create_ssl_context(void) {
    SSL_CTX *ctx;
    
    /* 创建SSL上下文 */
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("[Client] Failed to create SSL context\n");
        return NULL;
    }
    
    /* 设置证书验证模式 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    /* 加载根证书用于验证服务端 */
    if (SSL_CTX_load_verify_locations(ctx, "./certs/root_cert.pem", NULL) != 1) {
        printf("[Client] Warning: Failed to load root certificate\n");
    }
    
    /* 设置客户端证书回调 */
    SSL_CTX_set_client_cert_cb(ctx, tee_client_cert_cb);
    
    /* 设置支持的TLS版本 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    /* 设置密码套件 */
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
    
    printf("[Client] SSL context created\n");
    return ctx;
}

/* 创建TCP连接 */
int create_tcp_connection(void) {
    int sock;
    struct sockaddr_in server_addr;
    
    /* 创建socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[Client] Socket creation failed");
        return -1;
    }
    
    /* 设置服务器地址 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    
    /* 连接服务器 */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[Client] Connection failed");
        close(sock);
        return -1;
    }
    
    printf("[Client] TCP connection established\n");
    return sock;
}

/* 执行SSL握手 */
int perform_ssl_handshake(SSL *ssl) {
    int ret;
    
    printf("[Client] Starting SSL handshake...\n");
    
    ret = SSL_connect(ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        printf("[Client] SSL handshake failed: error %d\n", ssl_error);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    printf("[Client] SSL handshake completed successfully\n");
    
    /* 显示连接信息 */
    printf("[Client] SSL Protocol: %s\n", SSL_get_version(ssl));
    printf("[Client] Cipher: %s\n", SSL_get_cipher(ssl));
    
    /* 验证服务端证书 */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        char *line = X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
        printf("[Client] Server certificate subject: %s\n", line);
        free(line);
        X509_free(server_cert);
    }
    
    return 1;
}

/* 发送和接收数据 */
void exchange_data(SSL *ssl) {
    const char *message = "Hello from TEE Client!";
    char buffer[1024];
    int bytes;
    
    /* 发送数据 */
    bytes = SSL_write(ssl, message, strlen(message));
    if (bytes > 0) {
        printf("[Client] Sent: %s\n", message);
    } else {
        printf("[Client] Failed to send data\n");
        return;
    }
    
    /* 接收响应 */
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Client] Received: %s\n", buffer);
    } else {
        printf("[Client] Failed to receive data\n");
    }
}

/* 主函数 */
int main(void) {
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1;
    int ret = 1;
    
    printf("=== TEE Provider SSL Client ===\n");
    
    /* 初始化OpenSSL */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    
    /* 初始化TEE Provider */
    if (!init_tee_provider()) {
        printf("[Client] Failed to initialize TEE provider\n");
        goto cleanup;
    }
    
    /* 创建SSL上下文 */
    ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        goto cleanup;
    }
    
    /* 创建TCP连接 */
    sock = create_tcp_connection();
    if (sock < 0) {
        goto cleanup;
    }
    
    /* 创建SSL连接 */
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("[Client] Failed to create SSL object\n");
        goto cleanup;
    }
    
    /* 绑定socket到SSL */
    if (SSL_set_fd(ssl, sock) != 1) {
        printf("[Client] Failed to bind SSL to socket\n");
        goto cleanup;
    }
    
    /* 执行SSL握手 */
    if (!perform_ssl_handshake(ssl)) {
        goto cleanup;
    }
    
    /* 数据交换 */
    exchange_data(ssl);
    
    printf("[Client] Connection completed successfully\n");
    ret = 0;
    
cleanup:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sock >= 0) {
        close(sock);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    
    /* 清理TEE Provider */
    if (g_tee_ctx) {
        tee_provider_teardown(g_tee_ctx);
    }
    
    /* 清理OpenSSL */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    
    printf("[Client] Cleanup completed\n");
    return ret;
}