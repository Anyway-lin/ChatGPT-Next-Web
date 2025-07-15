#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* 全局变量用于优雅关闭 */
static volatile int server_running = 1;

/* 信号处理函数 */
static void signal_handler(int sig) {
    printf("\n收到信号 %d，正在关闭服务器...\n", sig);
    server_running = 0;
}

/* 错误处理 */
static void handle_openssl_error(const char *msg) {
    fprintf(stderr, "OpenSSL Error in %s:\n", msg);
    ERR_print_errors_fp(stderr);
}

/* 创建TCP服务器socket */
static int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }
    
    /* 设置socket选项，允许地址重用 */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, 5) < 0) {
        perror("listen failed");
        close(sockfd);
        return -1;
    }
    
    printf("TLS服务器监听端口: %d\n", port);
    return sockfd;
}

/* 处理客户端连接 */
static void handle_client(SSL *ssl) {
    char buffer[4096];
    int bytes;
    
    printf("\n=== 处理新的客户端连接 ===\n");
    
    /* 执行TLS握手 */
    printf("开始TLS握手...\n");
    int ssl_ret = SSL_accept(ssl);
    if (ssl_ret != 1) {
        int ssl_error = SSL_get_error(ssl, ssl_ret);
        fprintf(stderr, "TLS握手失败 (返回值: %d, 错误码: %d)\n", ssl_ret, ssl_error);
        handle_openssl_error("SSL_accept");
        return;
    }
    
    printf("✓ TLS握手成功！\n");
    
    /* 显示连接信息 */
    printf("TLS版本: %s\n", SSL_get_version(ssl));
    printf("加密套件: %s\n", SSL_get_cipher(ssl));
    
    /* 验证客户端证书 */
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        printf("客户端证书验证: ");
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result == X509_V_OK) {
            printf("✓ 验证成功\n");
        } else {
            printf("✗ 验证失败 (错误码: %ld)\n", verify_result);
        }
        
        /* 显示客户端证书信息 */
        char *subject = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        printf("客户端证书主题: %s\n", subject);
        printf("客户端证书颁发者: %s\n", issuer);
        
        OPENSSL_free(subject);
        OPENSSL_free(issuer);
        X509_free(client_cert);
    } else {
        printf("客户端未提供证书\n");
    }
    
    /* 接收客户端数据 */
    printf("\n=== 数据交换 ===\n");
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("接收到客户端数据 (%d字节): %s\n", bytes, buffer);
        
        /* 发送响应 */
        const char *response = "Hello from TLS Server! Your TEE Provider works perfectly!";
        bytes = SSL_write(ssl, response, strlen(response));
        if (bytes > 0) {
            printf("发送响应 (%d字节): %s\n", bytes, response);
        } else {
            fprintf(stderr, "发送响应失败\n");
            handle_openssl_error("SSL_write");
        }
    } else {
        int ssl_error = SSL_get_error(ssl, bytes);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            printf("客户端正常关闭连接\n");
        } else {
            fprintf(stderr, "接收数据失败 (错误码: %d)\n", ssl_error);
            handle_openssl_error("SSL_read");
        }
    }
    
    printf("客户端连接处理完成\n");
}

/* TLS服务器主函数 */
int main(int argc, char *argv[]) {
    SSL_CTX *ctx = NULL;
    int server_fd = -1;
    int ret = 1;
    
    /* 参数检查 */
    if (argc != 4) {
        fprintf(stderr, "用法: %s <端口> <服务器证书文件> <服务器私钥文件>\n", argv[0]);
        fprintf(stderr, "示例: %s 8443 certs/server-cert.pem certs/server-key-nopass.pem\n", argv[0]);
        return 1;
    }
    
    int port = atoi(argv[1]);
    const char *cert_file = argv[2];
    const char *key_file = argv[3];
    
    printf("=== TLS服务器启动 ===\n");
    printf("监听端口: %d\n", port);
    printf("服务器证书: %s\n", cert_file);
    printf("服务器私钥: %s\n", key_file);
    
    /* 设置信号处理 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* 初始化OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /* 创建SSL上下文 */
    printf("\n=== 创建SSL上下文 ===\n");
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        handle_openssl_error("SSL_CTX_new");
        goto cleanup;
    }
    
    /* 设置TLS版本 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    /* 加载服务器证书 */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error: 无法加载服务器证书文件 %s\n", cert_file);
        handle_openssl_error("SSL_CTX_use_certificate_file");
        goto cleanup;
    }
    printf("服务器证书加载成功: %s\n", cert_file);
    
    /* 加载服务器私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error: 无法加载服务器私钥文件 %s\n", key_file);
        handle_openssl_error("SSL_CTX_use_PrivateKey_file");
        goto cleanup;
    }
    printf("服务器私钥加载成功: %s\n", key_file);
    
    /* 验证私钥和证书匹配 */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Error: 服务器私钥和证书不匹配\n");
        handle_openssl_error("SSL_CTX_check_private_key");
        goto cleanup;
    }
    printf("服务器私钥和证书匹配验证成功\n");
    
    /* 设置客户端证书验证 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    /* 加载CA证书用于验证客户端证书 */
    if (SSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", NULL) != 1) {
        fprintf(stderr, "Warning: 无法加载CA证书，客户端证书验证可能失败\n");
        /* 不强制要求CA证书，继续运行 */
    } else {
        printf("CA证书加载成功，将验证客户端证书\n");
    }
    
    /* 创建服务器socket */
    printf("\n=== 创建服务器Socket ===\n");
    server_fd = create_server_socket(port);
    if (server_fd < 0) {
        goto cleanup;
    }
    
    printf("\n=== 服务器就绪，等待客户端连接 ===\n");
    printf("使用 Ctrl+C 停止服务器\n");
    
    /* 主服务循环 */
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd;
        SSL *ssl = NULL;
        
        /* 等待客户端连接 */
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (server_running) {
                perror("accept failed");
            }
            continue;
        }
        
        printf("\n新客户端连接来自: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        /* 创建SSL连接 */
        ssl = SSL_new(ctx);
        if (!ssl) {
            handle_openssl_error("SSL_new");
            close(client_fd);
            continue;
        }
        
        /* 绑定socket到SSL */
        if (SSL_set_fd(ssl, client_fd) != 1) {
            handle_openssl_error("SSL_set_fd");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        
        /* 处理客户端 */
        handle_client(ssl);
        
        /* 清理连接 */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    
    printf("\n✓ TLS服务器正常关闭\n");
    ret = 0;
    
cleanup:
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (server_fd >= 0) {
        close(server_fd);
    }
    
    EVP_cleanup();
    ERR_free_strings();
    
    return ret;
}