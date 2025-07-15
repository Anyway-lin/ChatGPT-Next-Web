#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>

static volatile int server_running = 1;

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down server...\n", sig);
    server_running = 0;
}

/* 创建服务器socket */
static int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        return -1;
    }
    
    /* 设置地址重用 */
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        return -1;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, 5) < 0) {
        perror("Unable to listen");
        close(sockfd);
        return -1;
    }
    
    printf("Server listening on port %d\n", port);
    return sockfd;
}

/* 创建SSL上下文 */
static SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    return ctx;
}

/* 配置SSL上下文 */
static int configure_ssl_context(SSL_CTX *ctx) {
    /* 设置证书 */
    if (SSL_CTX_use_certificate_file(ctx, "certs/server_cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* 设置私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* 验证私钥 */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return 0;
    }
    
    /* 设置客户端证书验证 - 暂时使用宽松模式 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    /* 加载CA证书 */
    if (!SSL_CTX_load_verify_locations(ctx, "certs/root_ca_cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        printf("Warning: Failed to load CA certificate, client authentication may fail\n");
    }
    
    printf("SSL context configured successfully\n");
    return 1;
}

/* 处理客户端连接 */
static void handle_client(SSL *ssl) {
    char buffer[4096];
    int bytes;
    
    printf("=== Processing client connection ===\n");
    
    /* 执行SSL握手 */
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("SSL handshake failed\n");
        return;
    }
    
    printf("SSL handshake successful\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    printf("Protocol: %s\n", SSL_get_version(ssl));
    
    /* 显示客户端证书信息 */
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        char *subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(client_cert), NULL, 0);
        printf("Client certificate subject: %s\n", subject);
        printf("Client certificate issuer: %s\n", issuer);
        OPENSSL_free(subject);
        OPENSSL_free(issuer);
        X509_free(client_cert);
    } else {
        printf("No client certificate provided\n");
    }
    
    /* 读取客户端请求 */
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Received request (%d bytes):\n%s\n", bytes, buffer);
        
        /* 发送简单的HTTP响应 */
        const char *response = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 137\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body>"
            "<h1>TEE Provider TLS Server</h1>"
            "<p>Successfully connected using TEE Provider!</p>"
            "<p>TLS handshake completed.</p>"
            "</body></html>";
        
        SSL_write(ssl, response, strlen(response));
        printf("Sent HTTP response\n");
    } else {
        printf("Failed to read client request\n");
        ERR_print_errors_fp(stderr);
    }
}

int main(int argc, char *argv[]) {
    int port = 8443;
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf("=== TEE Provider TLS Test Server ===\n");
    printf("Starting server on port %d\n", port);
    
    /* 设置信号处理 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* 初始化OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /* 创建SSL上下文 */
    SSL_CTX *ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        return 1;
    }
    
    /* 配置SSL上下文 */
    if (!configure_ssl_context(ssl_ctx)) {
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    
    /* 创建服务器socket */
    int server_fd = create_server_socket(port);
    if (server_fd < 0) {
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    
    printf("Server ready, waiting for connections...\n");
    printf("Press Ctrl+C to stop the server\n\n");
    
    /* 主服务循环 */
    while (server_running) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        
        /* 使用select来避免阻塞accept */
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (server_running) {
                perror("select error");
            }
            break;
        }
        
        if (activity == 0) {
            /* 超时，继续循环 */
            continue;
        }
        
        if (FD_ISSET(server_fd, &readfds)) {
            int client_fd = accept(server_fd, (struct sockaddr*)&addr, &len);
            if (client_fd < 0) {
                if (server_running) {
                    perror("Unable to accept");
                }
                continue;
            }
            
            printf("New connection from %s:%d\n", 
                   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            
            /* 创建SSL连接 */
            SSL *ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_fd);
            
            /* 处理客户端 */
            handle_client(ssl);
            
            /* 清理连接 */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            
            printf("Connection closed\n\n");
        }
    }
    
    /* 清理资源 */
    printf("Shutting down server...\n");
    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    
    printf("Server shutdown complete\n");
    return 0;
}