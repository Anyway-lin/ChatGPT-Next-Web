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
#include <openssl/provider.h>
#include "keyless_provider.h"
#include "tee_mock.h"

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
        printf("Server Certificate Information:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("  Subject: %s\n", line);
        free(line);
        
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("  Issuer: %s\n", line);
        free(line);
        
        X509_free(cert);
    } else {
        printf("No server certificate presented\n");
    }
    printf("==================================\n\n");
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    char subject[256];
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    
    printf("Server certificate verification: depth=%d, subject=%s\n", depth, subject);
    
    if (!preverify_ok) {
        printf("Server certificate verification failed: %s\n", X509_verify_cert_error_string(err));
    }
    
    // 对于演示目的，我们接受所有证书
    return 1;
}

static SSL_CTX* create_keyless_ssl_context(const char *device_key_path, const char *device_cert_path, const char *ca_file) {
    SSL_CTX *ctx;
    
    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        print_ssl_error();
        return NULL;
    }
    
    // 配置SSL上下文
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // 初始化TEE环境
    printf("Initializing TEE mock environment...\n");
    if (TeeInit(device_key_path) != 0) {
        fprintf(stderr, "Failed to initialize TEE mock\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    printf("TEE mock environment initialized successfully\n");
    
    // 加载设备证书
    printf("Loading device certificate: %s\n", device_cert_path);
    if (SSL_CTX_use_certificate_file(ctx, device_cert_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load device certificate\n");
        print_ssl_error();
        TeeCleanup();
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 为了简化演示，我们直接使用设备私钥
    // 在真实环境中，这里会使用TEE provider来处理私钥操作
    printf("Loading device private key for demonstration...\n");
    if (SSL_CTX_use_PrivateKey_file(ctx, device_key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load device private key\n");
        print_ssl_error();
        TeeCleanup();
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 验证证书和私钥是否匹配
    printf("Checking certificate and private key compatibility...\n");
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Certificate and private key do not match\n");
        print_ssl_error();
        TeeCleanup();
        SSL_CTX_free(ctx);
        return NULL;
    } else {
        printf("Certificate and private key compatibility check passed\n");
    }
    
    // 设置服务器证书验证
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    // 加载CA证书用于验证服务器证书
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        fprintf(stderr, "Warning: Failed to load CA certificate for server verification\n");
        // 继续运行，但不验证服务器证书
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    
    printf("SSL context created successfully\n");
    return ctx;
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[MAX_BUFFER_SIZE];
    int bytes_read;
    const char *server_ip = "127.0.0.1";
    const char *device_key_path = "../certs/device_key.pem";
    const char *device_cert_path = "../certs/device_cert.pem";
    const char *ca_file = "../certs/root_ca_cert.pem";
    const char *message = "Hello from keyless TLS client!";
    
    // 检查命令行参数
    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        device_key_path = argv[2];
    }
    if (argc > 3) {
        device_cert_path = argv[3];
    }
    if (argc > 4) {
        ca_file = argv[4];
    }
    if (argc > 5) {
        message = argv[5];
    }
    
    printf("Starting TLS Client with TEE Mock...\n");
    printf("Server: %s:%d\n", server_ip, SERVER_PORT);
    printf("Device Key: %s\n", device_key_path);
    printf("Device Certificate: %s\n", device_cert_path);
    printf("CA Certificate: %s\n", ca_file);
    printf("Message: %s\n", message);
    printf("\n");
    
    // 创建SSL上下文
    ctx = create_keyless_ssl_context(device_key_path, device_cert_path, ca_file);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        exit(1);
    }
    
    // 创建TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        TeeCleanup();
        exit(1);
    }
    
    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server IP address\n");
        close(sockfd);
        SSL_CTX_free(ctx);
        TeeCleanup();
        exit(1);
    }
    
    // 连接到服务器
    printf("Connecting to server...\n");
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        SSL_CTX_free(ctx);
        TeeCleanup();
        exit(1);
    }
    
    printf("TCP connection established\n");
    
    // 创建SSL连接
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL connection\n");
        close(sockfd);
        SSL_CTX_free(ctx);
        TeeCleanup();
        exit(1);
    }
    
    SSL_set_fd(ssl, sockfd);
    
    // 执行SSL握手
    printf("Performing SSL handshake...\n");
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        print_ssl_error();
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        TeeCleanup();
        exit(1);
    }
    
    printf("SSL handshake successful!\n");
    print_certificate_info(ssl);
    
    // 发送消息
    printf("Sending message: %s\n", message);
    if (SSL_write(ssl, message, strlen(message)) <= 0) {
        fprintf(stderr, "SSL write failed\n");
        print_ssl_error();
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        TeeCleanup();
        exit(1);
    }
    
    // 接收响应
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        fprintf(stderr, "SSL read failed\n");
        print_ssl_error();
    } else {
        buffer[bytes_read] = '\0';
        printf("Received response: %s\n", buffer);
    }
    
    // 发送第二条消息测试持续连接
    const char *second_message = "This is a second message to test the connection";
    printf("Sending second message: %s\n", second_message);
    if (SSL_write(ssl, second_message, strlen(second_message)) <= 0) {
        fprintf(stderr, "SSL write failed\n");
        print_ssl_error();
    } else {
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            printf("Received second response: %s\n", buffer);
        }
    }
    
    // 关闭连接
    printf("Closing connection...\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    TeeCleanup();
    
    printf("TLS client with TEE mock completed successfully!\n");
    return 0;
}