#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

// 默认配置
#define DEFAULT_PORT 4433
#define DEFAULT_CERT_FILE "./certs/server.pem"
#define DEFAULT_KEY_FILE "./certs/server.key"
#define DEFAULT_CA_FILE "./certs/ca.pem"
#define BUFFER_SIZE 4096

// 全局变量
static int server_running = 1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\n[INFO] 接收到终止信号，关闭服务器...\n");
        server_running = 0;
    }
}

// 日志函数
void log_message(const char *level, const char *message) {
    printf("[%s] %s\n", level, message);
}

// 错误处理函数
void handle_openssl_error(const char *msg) {
    unsigned long err;
    char err_buf[256];
    
    log_message("ERROR", msg);
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL Error: %s\n", err_buf);
    }
}

// 初始化SSL上下文
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx;
    
    log_message("INFO", "创建SSL上下文");
    
    // 创建SSL上下文 (支持TLS 1.2以触发客户端证书签名)
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (!ctx) {
        handle_openssl_error("无法创建SSL上下文");
        return NULL;
    }
    
    log_message("INFO", "使用TLS 1.2以支持客户端证书签名验证");
    
    // 设置验证模式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    // 加载CA证书
    if (SSL_CTX_load_verify_locations(ctx, DEFAULT_CA_FILE, NULL) <= 0) {
        handle_openssl_error("无法加载CA证书");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 加载服务器证书
    if (SSL_CTX_use_certificate_file(ctx, DEFAULT_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error("无法加载服务器证书");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 加载服务器私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, DEFAULT_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error("无法加载服务器私钥");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 验证私钥和证书匹配
    if (SSL_CTX_check_private_key(ctx) <= 0) {
        handle_openssl_error("私钥和证书不匹配");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    log_message("INFO", "SSL上下文创建成功");
    return ctx;
}

// 创建服务器socket
int create_server_socket(int port) {
    int sockfd, optval = 1;
    struct sockaddr_in server_addr;
    
    // 创建socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Socket创建失败: %s\n", strerror(errno));
        return -1;
    }
    
    // 设置socket选项
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        printf("设置socket选项失败: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    // 绑定地址
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("绑定地址失败: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    // 监听连接
    if (listen(sockfd, 5) < 0) {
        printf("监听失败: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    log_message("INFO", "服务器socket创建成功");
    return sockfd;
}

// 处理客户端连接
void handle_client(SSL *ssl, int client_fd) {
    char buffer[BUFFER_SIZE];
    int bytes_read, bytes_written;
    X509 *client_cert;
    char *line;
    
    // 执行TLS握手
    if (SSL_accept(ssl) <= 0) {
        handle_openssl_error("TLS握手失败");
        return;
    }
    
    log_message("INFO", "TLS握手成功");
    
    // 显示客户端证书信息
    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        printf("客户端证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        printf("  Subject: %s\n", line);
        OPENSSL_free(line);
        
        line = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        printf("  Issuer: %s\n", line);
        OPENSSL_free(line);
        
        X509_free(client_cert);
    }
    
    // 显示连接信息
    printf("协议版本: %s\n", SSL_get_version(ssl));
    printf("密码套件: %s\n", SSL_get_cipher(ssl));
    
    // 读取客户端数据
    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("接收到客户端数据:\n%s\n", buffer);
        
        // 发送HTTP响应
        char response[2048];
        snprintf(response, sizeof(response), 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head><title>TLS Server</title></head>\n"
            "<body>\n"
            "<h1>TLS连接成功！</h1>\n"
            "<p>这是一个基于OpenSSL的TLS服务器响应。</p>\n"
            "<p>使用的协议版本: %s</p>\n"
            "<p>使用的密码套件: %s</p>\n"
            "</body>\n"
            "</html>\n",
            SSL_get_version(ssl), SSL_get_cipher(ssl));
        
        bytes_written = SSL_write(ssl, response, strlen(response));
        if (bytes_written <= 0) {
            handle_openssl_error("发送响应失败");
            break;
        }
        
        printf("已发送 %d 字节响应\n", bytes_written);
        break; // 发送完响应后结束连接
    }
    
    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        if (ssl_error != SSL_ERROR_ZERO_RETURN) {
            printf("读取客户端数据失败，错误码: %d\n", ssl_error);
        }
    }
}

// 显示使用说明
void show_usage(const char *program) {
    printf("使用方法: %s [选项]\n", program);
    printf("选项:\n");
    printf("  -p <port>     服务器端口 (默认: %d)\n", DEFAULT_PORT);
    printf("  -c <cert>     服务器证书文件 (默认: %s)\n", DEFAULT_CERT_FILE);
    printf("  -k <key>      服务器私钥文件 (默认: %s)\n", DEFAULT_KEY_FILE);
    printf("  -C <ca>       CA证书文件 (默认: %s)\n", DEFAULT_CA_FILE);
    printf("  --help        显示此帮助信息\n");
}

// 主函数
int main(int argc, char *argv[]) {
    SSL_CTX *ssl_ctx = NULL;
    int server_fd = -1;
    int port = DEFAULT_PORT;
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            show_usage(argv[0]);
            return 0;
        }
    }
    
    printf("=== TLS服务器 ===\n");
    printf("监听端口: %d\n", port);
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // 创建SSL上下文
    ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        log_message("ERROR", "无法创建SSL上下文");
        return 1;
    }
    
    // 创建服务器socket
    server_fd = create_server_socket(port);
    if (server_fd < 0) {
        log_message("ERROR", "无法创建服务器socket");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    
    printf("服务器启动成功，监听端口 %d\n", port);
    printf("按 Ctrl+C 停止服务器\n");
    
    // 主循环
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd;
        SSL *ssl;
        
        // 等待客户端连接
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue; // 被信号中断，继续等待
            }
            printf("接受连接失败: %s\n", strerror(errno));
            continue;
        }
        
        printf("接收到来自 %s:%d 的连接\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // 创建SSL对象
        ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            handle_openssl_error("无法创建SSL对象");
            close(client_fd);
            continue;
        }
        
        // 设置文件描述符
        SSL_set_fd(ssl, client_fd);
        
        // 处理客户端
        handle_client(ssl, client_fd);
        
        // 关闭连接
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        
        log_message("INFO", "客户端连接处理完成");
    }
    
    // 清理资源
    if (server_fd >= 0) {
        close(server_fd);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    
    EVP_cleanup();
    ERR_free_strings();
    
    printf("服务器已停止\n");
    return 0;
}