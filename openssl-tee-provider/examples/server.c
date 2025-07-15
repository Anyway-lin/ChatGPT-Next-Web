#include "../src/tee_provider.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_PORT 8443
#define MAX_CLIENTS 5

/* 证书验证回调函数 */
int cert_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    
    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    
    printf("[Server] Verifying certificate:\n");
    printf("[Server]   Depth: %d\n", depth);
    printf("[Server]   Subject: %s\n", subject ? subject : "Unknown");
    printf("[Server]   Issuer: %s\n", issuer ? issuer : "Unknown");
    
    if (!preverify_ok) {
        printf("[Server]   Error: %s\n", X509_verify_cert_error_string(err));
    } else {
        printf("[Server]   Verification: OK\n");
    }
    
    if (subject) free(subject);
    if (issuer) free(issuer);
    
    /* 接受所有证书（仅用于演示，生产环境需要严格验证） */
    return 1;
}

/* 创建SSL上下文 */
SSL_CTX *create_ssl_context(void) {
    SSL_CTX *ctx;
    
    /* 创建SSL上下文 */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        printf("[Server] Failed to create SSL context\n");
        return NULL;
    }
    
    /* 设置证书验证模式 - 要求客户端证书 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_callback);
    
    /* 加载服务器证书 */
    if (SSL_CTX_use_certificate_file(ctx, "./certs/server_cert.pem", SSL_FILETYPE_PEM) != 1) {
        printf("[Server] Failed to load server certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* 加载服务器私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/server_key.pem", SSL_FILETYPE_PEM) != 1) {
        printf("[Server] Failed to load server private key\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* 验证私钥与证书匹配 */
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("[Server] Server private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* 加载CA证书用于验证客户端证书 */
    if (SSL_CTX_load_verify_locations(ctx, "./certs/root_cert.pem", NULL) != 1) {
        printf("[Server] Warning: Failed to load CA certificate\n");
    }
    
    /* 设置证书链 */
    if (SSL_CTX_use_certificate_chain_file(ctx, "./certs/server_cert.pem") != 1) {
        printf("[Server] Warning: Failed to load certificate chain\n");
    }
    
    /* 设置支持的TLS版本 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    /* 设置密码套件 */
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
    
    printf("[Server] SSL context created successfully\n");
    return ctx;
}

/* 创建TCP服务器socket */
int create_server_socket(void) {
    int server_sock;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    /* 创建socket */
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("[Server] Socket creation failed");
        return -1;
    }
    
    /* 设置socket选项 */
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[Server] Setsockopt failed");
        close(server_sock);
        return -1;
    }
    
    /* 设置服务器地址 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    /* 绑定socket */
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[Server] Bind failed");
        close(server_sock);
        return -1;
    }
    
    /* 开始监听 */
    if (listen(server_sock, MAX_CLIENTS) < 0) {
        perror("[Server] Listen failed");
        close(server_sock);
        return -1;
    }
    
    printf("[Server] Server listening on port %d\n", SERVER_PORT);
    return server_sock;
}

/* 处理SSL握手 */
int perform_ssl_handshake(SSL *ssl) {
    int ret;
    
    printf("[Server] Starting SSL handshake...\n");
    
    ret = SSL_accept(ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        printf("[Server] SSL handshake failed: error %d\n", ssl_error);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    printf("[Server] SSL handshake completed successfully\n");
    
    /* 显示连接信息 */
    printf("[Server] SSL Protocol: %s\n", SSL_get_version(ssl));
    printf("[Server] Cipher: %s\n", SSL_get_cipher(ssl));
    
    /* 获取客户端证书信息 */
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        char *line = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
        printf("[Server] Client certificate subject: %s\n", line);
        free(line);
        
        /* 验证证书链 */
        STACK_OF(X509) *cert_chain = SSL_get_peer_cert_chain(ssl);
        if (cert_chain) {
            int chain_len = sk_X509_num(cert_chain);
            printf("[Server] Certificate chain length: %d\n", chain_len);
            
            for (int i = 0; i < chain_len; i++) {
                X509 *cert = sk_X509_value(cert_chain, i);
                char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
                printf("[Server]   Chain[%d]: %s\n", i, subject ? subject : "Unknown");
                if (subject) free(subject);
            }
        }
        
        X509_free(client_cert);
    } else {
        printf("[Server] No client certificate provided\n");
    }
    
    return 1;
}

/* 处理客户端连接 */
void handle_client(SSL *ssl) {
    char buffer[1024];
    int bytes;
    
    /* 接收客户端数据 */
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("[Server] Received: %s\n", buffer);
        
        /* 发送响应 */
        const char *response = "Hello from TEE Server! Certificate authentication successful.";
        bytes = SSL_write(ssl, response, strlen(response));
        if (bytes > 0) {
            printf("[Server] Sent: %s\n", response);
        } else {
            printf("[Server] Failed to send response\n");
        }
    } else {
        int ssl_error = SSL_get_error(ssl, bytes);
        printf("[Server] Failed to read data: error %d\n", ssl_error);
    }
}

/* 主函数 */
int main(void) {
    SSL_CTX *ssl_ctx = NULL;
    int server_sock = -1;
    int client_sock = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL *ssl = NULL;
    
    printf("=== TEE Provider SSL Server ===\n");
    
    /* 初始化OpenSSL */
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    
    /* 创建SSL上下文 */
    ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        goto cleanup;
    }
    
    /* 创建服务器socket */
    server_sock = create_server_socket();
    if (server_sock < 0) {
        goto cleanup;
    }
    
    printf("[Server] Waiting for client connections...\n");
    
    /* 主服务循环 */
    while (1) {
        /* 接受客户端连接 */
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("[Server] Accept failed");
            continue;
        }
        
        printf("[Server] Client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        /* 创建SSL连接 */
        ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            printf("[Server] Failed to create SSL object\n");
            close(client_sock);
            continue;
        }
        
        /* 绑定socket到SSL */
        if (SSL_set_fd(ssl, client_sock) != 1) {
            printf("[Server] Failed to bind SSL to socket\n");
            SSL_free(ssl);
            close(client_sock);
            continue;
        }
        
        /* 执行SSL握手 */
        if (perform_ssl_handshake(ssl)) {
            /* 处理客户端请求 */
            handle_client(ssl);
        }
        
        /* 清理连接 */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        ssl = NULL;
        client_sock = -1;
        
        printf("[Server] Client connection closed\n");
        printf("[Server] Waiting for next client...\n");
    }
    
cleanup:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (client_sock >= 0) {
        close(client_sock);
    }
    if (server_sock >= 0) {
        close(server_sock);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    
    /* 清理OpenSSL */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    
    printf("[Server] Server shutdown completed\n");
    return 0;
}