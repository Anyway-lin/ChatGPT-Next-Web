#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <dlfcn.h>

#include "tee_provider.h"

// 默认配置
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 4433
#define DEFAULT_CA_FILE "./certs/ca.pem"
#define DEFAULT_CLIENT_CERT "./certs/client.pem"
#define DEFAULT_CLIENT_KEY "./certs/client.key"
#define PROVIDER_LIB_PATH "./build/libtee_provider.so"

// 全局变量
static OSSL_PROVIDER *tee_provider = NULL;
static void *provider_handle = NULL;

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

// 加载TEE Provider
int load_tee_provider(OSSL_LIB_CTX *libctx) {
    log_message("INFO", "开始加载TEE Provider");
    
    // 动态加载provider库
    provider_handle = dlopen(PROVIDER_LIB_PATH, RTLD_LAZY);
    if (!provider_handle) {
        printf("无法加载provider库: %s\n", dlerror());
        return 0;
    }
    
    // 获取provider初始化函数
    int (*provider_init)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **) = 
        dlsym(provider_handle, "OSSL_provider_init");
    if (!provider_init) {
        printf("无法找到provider初始化函数: %s\n", dlerror());
        dlclose(provider_handle);
        return 0;
    }
    
    // 加载provider
    tee_provider = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_provider) {
        // 如果加载失败，尝试添加provider路径
        if (OSSL_PROVIDER_add_builtin(libctx, "tee", provider_init) == 0) {
            handle_openssl_error("无法添加TEE Provider");
            dlclose(provider_handle);
            return 0;
        }
        
        tee_provider = OSSL_PROVIDER_load(libctx, "tee");
        if (!tee_provider) {
            handle_openssl_error("无法加载TEE Provider");
            dlclose(provider_handle);
            return 0;
        }
    }
    
    log_message("INFO", "TEE Provider加载成功");
    return 1;
}

// 卸载TEE Provider
void unload_tee_provider() {
    if (tee_provider) {
        OSSL_PROVIDER_unload(tee_provider);
        tee_provider = NULL;
    }
    if (provider_handle) {
        dlclose(provider_handle);
        provider_handle = NULL;
    }
}

// 创建TCP连接
int create_tcp_connection(const char *host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    
    // 创建socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Socket创建失败: %s\n", strerror(errno));
        return -1;
    }
    
    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        printf("无效的IP地址: %s\n", host);
        close(sockfd);
        return -1;
    }
    
    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("连接失败: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    log_message("INFO", "TCP连接建立成功");
    return sockfd;
}

// 初始化SSL上下文
SSL_CTX *create_ssl_context(OSSL_LIB_CTX *libctx) {
    SSL_CTX *ctx;
    
    log_message("INFO", "创建SSL上下文");
    
    // 创建SSL上下文
    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (!ctx) {
        handle_openssl_error("无法创建SSL上下文");
        return NULL;
    }
    
    // 设置验证模式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    // 加载CA证书
    if (SSL_CTX_load_verify_locations(ctx, DEFAULT_CA_FILE, NULL) <= 0) {
        handle_openssl_error("无法加载CA证书");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 加载客户端证书
    if (SSL_CTX_use_certificate_file(ctx, DEFAULT_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error("无法加载客户端证书");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // 设置使用TEE Provider进行私钥操作
    // 这里我们不直接加载私钥，而是让provider处理
    log_message("INFO", "配置使用TEE Provider进行私钥操作");
    
    return ctx;
}

// 执行TLS握手
int perform_tls_handshake(SSL *ssl, int sockfd) {
    int result;
    
    log_message("INFO", "开始TLS握手");
    
    // 设置socket fd
    SSL_set_fd(ssl, sockfd);
    
    // 执行握手
    result = SSL_connect(ssl);
    if (result <= 0) {
        int ssl_error = SSL_get_error(ssl, result);
        printf("TLS握手失败，错误码: %d\n", ssl_error);
        handle_openssl_error("TLS握手失败");
        return 0;
    }
    
    log_message("INFO", "TLS握手成功");
    return 1;
}

// 显示连接信息
void show_connection_info(SSL *ssl) {
    X509 *cert;
    char *line;
    
    log_message("INFO", "连接信息:");
    
    // 显示使用的协议版本
    printf("协议版本: %s\n", SSL_get_version(ssl));
    
    // 显示使用的密码套件
    printf("密码套件: %s\n", SSL_get_cipher(ssl));
    
    // 显示服务器证书信息
    cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        printf("服务器证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("  Subject: %s\n", line);
        OPENSSL_free(line);
        
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("  Issuer: %s\n", line);
        OPENSSL_free(line);
        
        X509_free(cert);
    }
}

// 发送和接收数据
int exchange_data(SSL *ssl) {
    const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    char buffer[4096];
    int bytes_written, bytes_read;
    
    log_message("INFO", "发送HTTP请求");
    
    // 发送请求
    bytes_written = SSL_write(ssl, request, strlen(request));
    if (bytes_written <= 0) {
        handle_openssl_error("发送数据失败");
        return 0;
    }
    
    printf("已发送 %d 字节数据\n", bytes_written);
    
    // 接收响应
    log_message("INFO", "接收服务器响应");
    while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("接收到数据:\n%s\n", buffer);
    }
    
    return 1;
}

// 清理资源
void cleanup(SSL *ssl, SSL_CTX *ctx, int sockfd, OSSL_LIB_CTX *libctx) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    unload_tee_provider();
    if (libctx) {
        OSSL_LIB_CTX_free(libctx);
    }
}

// 显示使用说明
void show_usage(const char *program) {
    printf("使用方法: %s [选项]\n", program);
    printf("选项:\n");
    printf("  -h <host>     服务器地址 (默认: %s)\n", DEFAULT_HOST);
    printf("  -p <port>     服务器端口 (默认: %d)\n", DEFAULT_PORT);
    printf("  -c <cert>     客户端证书文件 (默认: %s)\n", DEFAULT_CLIENT_CERT);
    printf("  -k <key>      客户端私钥文件 (默认: %s)\n", DEFAULT_CLIENT_KEY);
    printf("  -C <ca>       CA证书文件 (默认: %s)\n", DEFAULT_CA_FILE);
    printf("  -v            显示详细信息\n");
    printf("  --help        显示此帮助信息\n");
}

// 主函数
int main(int argc, char *argv[]) {
    OSSL_LIB_CTX *libctx = NULL;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int sockfd = -1;
    int result = 0;
    
    // 解析命令行参数
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    const char *client_cert = DEFAULT_CLIENT_CERT;
    const char *client_key = DEFAULT_CLIENT_KEY;
    const char *ca_file = DEFAULT_CA_FILE;
    int verbose = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            client_cert = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            client_key = argv[++i];
        } else if (strcmp(argv[i], "-C") == 0 && i + 1 < argc) {
            ca_file = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            show_usage(argv[0]);
            return 0;
        }
    }
    
    printf("=== 基于TEE Provider的TLS客户端 ===\n");
    printf("连接目标: %s:%d\n", host, port);
    
    // 创建OpenSSL库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        handle_openssl_error("无法创建OpenSSL库上下文");
        return 1;
    }
    
    // 设置TEE Provider的私钥路径
    tee_provider_set_private_key_path(client_key);
    
    // 加载TEE Provider
    if (!load_tee_provider(libctx)) {
        log_message("ERROR", "无法加载TEE Provider");
        cleanup(ssl, ssl_ctx, sockfd, libctx);
        return 1;
    }
    
    // 创建SSL上下文
    ssl_ctx = create_ssl_context(libctx);
    if (!ssl_ctx) {
        log_message("ERROR", "无法创建SSL上下文");
        cleanup(ssl, ssl_ctx, sockfd, libctx);
        return 1;
    }
    
    // 创建TCP连接
    sockfd = create_tcp_connection(host, port);
    if (sockfd < 0) {
        log_message("ERROR", "无法建立TCP连接");
        cleanup(ssl, ssl_ctx, sockfd, libctx);
        return 1;
    }
    
    // 创建SSL对象
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        handle_openssl_error("无法创建SSL对象");
        cleanup(ssl, ssl_ctx, sockfd, libctx);
        return 1;
    }
    
    // 执行TLS握手
    if (!perform_tls_handshake(ssl, sockfd)) {
        log_message("ERROR", "TLS握手失败");
        cleanup(ssl, ssl_ctx, sockfd, libctx);
        return 1;
    }
    
    // 显示连接信息
    show_connection_info(ssl);
    
    // 交换数据
    if (exchange_data(ssl)) {
        log_message("INFO", "数据交换成功");
        result = 0;
    } else {
        log_message("ERROR", "数据交换失败");
        result = 1;
    }
    
    // 清理资源
    cleanup(ssl, ssl_ctx, sockfd, libctx);
    
    printf("=== 程序结束 ===\n");
    return result;
}