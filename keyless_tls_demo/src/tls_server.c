#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define SERVER_PORT 8443
#define MAX_BUFFER_SIZE 4096

static void print_ssl_error(void) {
    unsigned long err;
    char err_buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "SSL Error: %s\n", err_buf);
    }
}

static void print_certificate_info(SSL *ssl) {
    X509 *cert;
    char *line;
    
    printf("\n=== SSL Connection Information ===\n");
    printf("SSL Version: %s\n", SSL_get_version(ssl));
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Client Certificate Information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("  Subject: %s\n", line);
        free(line);
        
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("  Issuer: %s\n", line);
        free(line);
        
        X509_free(cert);
    } else {
        printf("No client certificate presented\n");
    }
    printf("==================================\n\n");
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    char subject[256];
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    
    printf("Certificate verification: depth=%d, subject=%s\n", depth, subject);
    
    if (!preverify_ok) {
        printf("Certificate verification failed: %s\n", X509_verify_cert_error_string(err));
    }
    
    // 对于演示目的，我们接受所有证书
    return 1;
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[MAX_BUFFER_SIZE];
    int bytes_read;
    const char *cert_file = "../certs/server_cert.pem";
    const char *key_file = "../certs/server_key.pem";
    const char *ca_file = "../certs/root_ca_cert.pem";
    
    // 检查命令行参数
    if (argc > 1) {
        cert_file = argv[1];
    }
    if (argc > 2) {
        key_file = argv[2];
    }
    if (argc > 3) {
        ca_file = argv[3];
    }
    
    printf("Starting TLS Server...\n");
    printf("Certificate: %s\n", cert_file);
    printf("Private Key: %s\n", key_file);
    printf("CA Certificate: %s\n", ca_file);
    
    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        print_ssl_error();
        exit(1);
    }
    
    // 配置SSL上下文
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // 加载服务器证书
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load server certificate\n");
        print_ssl_error();
        exit(1);
    }
    
    // 加载服务器私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load server private key\n");
        print_ssl_error();
        exit(1);
    }
    
    // 验证私钥和证书是否匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        exit(1);
    }
    
    // 设置客户端证书验证（可选）
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    
    // 加载CA证书用于验证客户端证书
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        fprintf(stderr, "Warning: Failed to load CA certificate for client verification\n");
        // 继续运行，但不验证客户端证书
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    
    // 创建TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }
    
    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    
    // 绑定地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(1);
    }
    
    // 监听连接
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        exit(1);
    }
    
    printf("TLS Server listening on port %d...\n", SERVER_PORT);
    
    while (1) {
        // 接受连接
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // 创建SSL连接
        ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "Failed to create SSL connection\n");
            close(client_fd);
            continue;
        }
        
        SSL_set_fd(ssl, client_fd);
        
        // 执行SSL握手
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "SSL handshake failed\n");
            print_ssl_error();
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        
        printf("SSL handshake successful!\n");
        print_certificate_info(ssl);
        
        // 处理客户端请求
        while (1) {
            bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) {
                int ssl_error = SSL_get_error(ssl, bytes_read);
                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    printf("Client closed connection\n");
                } else {
                    printf("SSL read error: %d\n", ssl_error);
                    print_ssl_error();
                }
                break;
            }
            
            buffer[bytes_read] = '\0';
            printf("Received: %s\n", buffer);
            
            // 回送消息
            char response[MAX_BUFFER_SIZE];
            snprintf(response, sizeof(response), 
                    "Server received: %s (Length: %d)", buffer, bytes_read);
            
            if (SSL_write(ssl, response, strlen(response)) <= 0) {
                fprintf(stderr, "SSL write failed\n");
                print_ssl_error();
                break;
            }
        }
        
        // 关闭SSL连接
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        printf("Client disconnected\n\n");
    }
    
    // 清理资源
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    return 0;
}