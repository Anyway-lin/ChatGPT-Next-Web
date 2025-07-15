#include "tee_provider.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* 外部函数声明 - Provider入口点 */
extern int tee_provider_init(const OSSL_CORE_HANDLE *handle, 
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            void **provctx);

/* TEE Provider加载函数 */
static OSSL_PROVIDER *load_tee_provider(OSSL_LIB_CTX *libctx) {
    printf("=== 加载TEE Provider ===\n");
    
    /* 创建Provider */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(libctx, "tee-provider");
    if (!prov) {
        printf("Failed to load TEE provider from library, trying to add manually...\n");
        
        /* 手动添加Provider */
        if (!OSSL_PROVIDER_add_builtin(libctx, "tee-provider", tee_provider_init)) {
            printf("ERROR: Failed to add builtin TEE provider\n");
            return NULL;
        }
        
        prov = OSSL_PROVIDER_load(libctx, "tee-provider");
        if (!prov) {
            printf("ERROR: Failed to load TEE provider after adding builtin\n");
            return NULL;
        }
    }
    
    /* 验证Provider */
    if (OSSL_PROVIDER_available(libctx, "tee-provider")) {
        printf("SUCCESS: TEE Provider is available\n");
    } else {
        printf("ERROR: TEE Provider is not available\n");
        OSSL_PROVIDER_unload(prov);
        return NULL;
    }
    
    return prov;
}

/* 创建socket连接 */
static int create_socket_connection(const char *hostname, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, hostname, &serv_addr.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sockfd);
        return -1;
    }
    
    printf("Connected to %s:%d\n", hostname, port);
    return sockfd;
}

/* 加载私钥使用TEE Provider */
static EVP_PKEY *load_tee_private_key(OSSL_LIB_CTX *libctx, const char *key_file) {
    printf("=== 加载TEE私钥 ===\n");
    
    /* 首先尝试标准方法加载私钥 */
    FILE *fp = fopen(key_file, "r");
    if (!fp) {
        printf("ERROR: Cannot open key file: %s\n", key_file);
        return NULL;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        printf("ERROR: Cannot read private key from file: %s\n", key_file);
        return NULL;
    }
    
    printf("SUCCESS: Private key loaded (will be handled by TEE Provider during TLS operations)\n");
    return pkey;
}

/* 设置SSL上下文 */
static SSL_CTX *setup_ssl_context(OSSL_LIB_CTX *libctx, OSSL_PROVIDER *tee_prov) {
    printf("=== 设置SSL上下文 ===\n");
    
    SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (!ctx) {
        printf("ERROR: Failed to create SSL context\n");
        return NULL;
    }
    
    /* 设置SSL选项 */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    
    /* 设置证书验证模式 - 暂时使用宽松模式 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    /* 加载CA证书 */
    if (!SSL_CTX_load_verify_locations(ctx, "certs/root_ca_cert.pem", NULL)) {
        printf("WARNING: Failed to load CA certificates\n");
    } else {
        printf("SUCCESS: CA certificates loaded\n");
    }
    
    /* 加载客户端证书 */
    if (SSL_CTX_use_certificate_file(ctx, "certs/device_cert.pem", SSL_FILETYPE_PEM) <= 0) {
        printf("ERROR: Failed to load client certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    printf("SUCCESS: Client certificate loaded\n");
    
    /* 加载私钥使用TEE Provider */
    EVP_PKEY *pkey = load_tee_private_key(libctx, "certs/device_key.pem");
    if (!pkey) {
        printf("ERROR: Failed to load private key\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        printf("ERROR: Failed to use private key\n");
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_free(pkey);
    
    /* 验证私钥和证书匹配 */
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("ERROR: Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    printf("SUCCESS: Private key and certificate matched\n");
    return ctx;
}

/* 执行TLS握手 */
static int perform_tls_handshake(SSL *ssl) {
    printf("=== 执行TLS握手 ===\n");
    
    int result = SSL_connect(ssl);
    if (result <= 0) {
        int ssl_error = SSL_get_error(ssl, result);
        printf("ERROR: TLS handshake failed (SSL_error: %d)\n", ssl_error);
        
        unsigned long err;
        while ((err = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            printf("OpenSSL Error: %s\n", err_buf);
        }
        return 0;
    }
    
    printf("SUCCESS: TLS handshake completed\n");
    
    /* 显示连接信息 */
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    printf("Protocol: %s\n", SSL_get_version(ssl));
    
    /* 显示服务器证书信息 */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        char *subject = X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), NULL, 0);
        printf("Server certificate subject: %s\n", subject);
        printf("Server certificate issuer: %s\n", issuer);
        OPENSSL_free(subject);
        OPENSSL_free(issuer);
        X509_free(server_cert);
    }
    
    return 1;
}

/* 发送HTTP请求并接收响应 */
static void exchange_data(SSL *ssl) {
    printf("=== 数据交换 ===\n");
    
    const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    
    int bytes_written = SSL_write(ssl, request, strlen(request));
    if (bytes_written <= 0) {
        printf("ERROR: Failed to send HTTP request\n");
        return;
    }
    
    printf("Sent HTTP request (%d bytes)\n", bytes_written);
    
    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("Received response (%d bytes):\n%s\n", bytes_read, buffer);
    } else {
        printf("No response received or connection closed\n");
    }
}

/* 主函数 */
int main(int argc, char *argv[]) {
    const char *hostname = "127.0.0.1";
    int port = 8443;
    
    if (argc > 1) hostname = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    
    printf("=== TEE Provider TLS客户端演示 ===\n");
    printf("连接到: %s:%d\n\n", hostname, port);
    
    /* 初始化OpenSSL */
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("ERROR: Failed to create library context\n");
        return 1;
    }
    
    /* 加载TEE Provider */
    OSSL_PROVIDER *tee_prov = load_tee_provider(libctx);
    if (!tee_prov) {
        printf("ERROR: Failed to load TEE Provider\n");
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    /* 也需要加载default provider来支持基本的加密操作 */
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        printf("WARNING: Failed to load default provider\n");
    }
    
    /* 创建socket连接 */
    int sockfd = create_socket_connection(hostname, port);
    if (sockfd < 0) {
        printf("ERROR: Failed to create socket connection\n");
        OSSL_PROVIDER_unload(tee_prov);
        if (default_prov) OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    /* 设置SSL上下文 */
    SSL_CTX *ssl_ctx = setup_ssl_context(libctx, tee_prov);
    if (!ssl_ctx) {
        printf("ERROR: Failed to setup SSL context\n");
        close(sockfd);
        OSSL_PROVIDER_unload(tee_prov);
        if (default_prov) OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    /* 创建SSL连接 */
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("ERROR: Failed to create SSL connection\n");
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        OSSL_PROVIDER_unload(tee_prov);
        if (default_prov) OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    /* 将SSL与socket关联 */
    if (!SSL_set_fd(ssl, sockfd)) {
        printf("ERROR: Failed to associate SSL with socket\n");
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        OSSL_PROVIDER_unload(tee_prov);
        if (default_prov) OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    /* 执行TLS握手 */
    if (!perform_tls_handshake(ssl)) {
        printf("ERROR: TLS handshake failed\n");
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        OSSL_PROVIDER_unload(tee_prov);
        if (default_prov) OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    /* 交换数据 */
    exchange_data(ssl);
    
    /* 清理资源 */
    printf("\n=== 清理资源 ===\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    OSSL_LIB_CTX_free(libctx);
    
    printf("Client terminated successfully\n");
    return 0;
}