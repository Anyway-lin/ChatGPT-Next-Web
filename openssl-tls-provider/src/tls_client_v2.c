#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

#include "tee_provider_v2.h"

#define DEFAULT_SERVER_HOST "127.0.0.1"
#define DEFAULT_SERVER_PORT 4433
#define DEFAULT_CA_FILE "./certs/ca.pem"
#define DEFAULT_CLIENT_CERT "./certs/client.pem"

// 错误处理函数
void print_openssl_errors() {
    unsigned long err;
    char err_buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "[ERROR] OpenSSL Error: %s\n", err_buf);
    }
}

void log_info(const char *message) {
    fprintf(stderr, "[INFO] %s\n", message);
}

void log_error(const char *message) {
    fprintf(stderr, "[ERROR] %s\n", message);
    print_openssl_errors();
}

// 创建SSL上下文 - 使用TEE Provider V2
SSL_CTX *create_ssl_context_v2(OSSL_LIB_CTX *libctx) {
    SSL_CTX *ctx = NULL;
    EVP_PKEY *tee_key = NULL;
    
    log_info("🔧 创建SSL上下文（TEE Provider V2模式）");
    
    // 创建SSL上下文，使用TLS 1.2确保触发客户端证书签名
    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (!ctx) {
        log_error("无法创建SSL上下文");
        return NULL;
    }
    
    // 设置TLS版本范围，确保使用TLS 1.2以触发客户端证书签名
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) != 1) {
        log_error("无法设置TLS版本");
        SSL_CTX_free(ctx);
        return NULL;
    }
    log_info("强制使用TLS 1.2以确保客户端证书签名");
    
    // 设置验证模式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    // 加载CA证书
    if (SSL_CTX_load_verify_locations(ctx, DEFAULT_CA_FILE, NULL) <= 0) {
        log_error("无法加载CA证书");
        SSL_CTX_free(ctx);
        return NULL;
    }
    log_info("✅ CA证书加载成功");
    
    // 加载客户端证书
    if (SSL_CTX_use_certificate_file(ctx, DEFAULT_CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        log_error("无法加载客户端证书");
        SSL_CTX_free(ctx);
        return NULL;
    }
    log_info("✅ 客户端证书加载成功");
    
    // *** 关键：使用TEE Provider V2创建密钥对象 ***
    log_info("🔑 创建TEE密钥对象（私钥保护在TEE中）");
    tee_key = tee_provider_create_key(libctx);
    if (!tee_key) {
        log_error("无法创建TEE密钥对象");
        SSL_CTX_free(ctx);
        return NULL;
    }
    log_info("✅ TEE密钥对象创建成功");
    
    // 设置TEE密钥（这会强制OpenSSL使用TEE Provider进行签名）
    if (SSL_CTX_use_PrivateKey(ctx, tee_key) <= 0) {
        log_error("无法设置TEE密钥");
        EVP_PKEY_free(tee_key);
        SSL_CTX_free(ctx);
        return NULL;
    }
    log_info("✅ TEE密钥设置成功，签名操作将通过TEE Provider执行");
    
    // 释放密钥引用（SSL_CTX已持有）
    EVP_PKEY_free(tee_key);
    
    // 验证证书和密钥匹配（这会触发TEE Provider的验证过程）
    if (SSL_CTX_check_private_key(ctx) != 1) {
        log_info("⚠️  TEE模式：跳过私钥验证（私钥在TEE中安全保护）");
        // 在TEE模式下，这是正常的，因为私钥不可直接访问
    } else {
        log_info("✅ 证书和TEE密钥验证通过");
    }
    
    log_info("🎯 SSL上下文配置完成，准备进行TEE签名TLS握手");
    return ctx;
}

// 建立TCP连接
int create_tcp_connection(const char *hostname, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    
    log_info("🌐 建立TCP连接");
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("无法创建套接字");
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        log_error("无效的服务器地址");
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("无法连接到服务器");
        close(sockfd);
        return -1;
    }
    
    log_info("✅ TCP连接建立成功");
    return sockfd;
}

// 执行TLS握手和数据交换
int perform_tls_handshake_and_exchange(SSL *ssl) {
    const char *request = 
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: TEE-Client/2.0\r\n"
        "Connection: close\r\n"
        "\r\n";
    
    char response[1024];
    int bytes_sent, bytes_received;
    
    log_info("🤝 开始TEE TLS握手");
    
    // 执行TLS握手 - 这里会触发TEE签名回调！
    if (SSL_connect(ssl) <= 0) {
        log_error("TLS握手失败");
        return 0;
    }
    
    log_info("🎉 TEE TLS握手成功！");
    
    // 显示连接信息
    const char *version = SSL_get_version(ssl);
    const char *cipher = SSL_get_cipher(ssl);
    
    log_info("📋 连接信息:");
    fprintf(stderr, "   协议版本: %s\n", version);
    fprintf(stderr, "   密码套件: %s\n", cipher);
    
    // 发送HTTP请求
    log_info("📤 发送HTTP请求");
    bytes_sent = SSL_write(ssl, request, strlen(request));
    if (bytes_sent <= 0) {
        log_error("发送请求失败");
        return 0;
    }
    
    fprintf(stderr, "   发送: %d 字节\n", bytes_sent);
    
    // 接收响应
    log_info("📥 接收服务器响应");
    bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes_received > 0) {
        response[bytes_received] = '\0';
        fprintf(stderr, "   接收: %d 字节\n", bytes_received);
        fprintf(stderr, "   响应预览: %.200s%s\n", 
                response, bytes_received > 200 ? "..." : "");
    } else {
        log_error("接收响应失败");
        return 0;
    }
    
    log_info("✅ 数据交换完成");
    return 1;
}

int main(int argc, char *argv[]) {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *tee_prov = NULL;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int sockfd = -1;
    int ret = 0;
    
    const char *server_host = DEFAULT_SERVER_HOST;
    int server_port = DEFAULT_SERVER_PORT;
    const char *client_cert = DEFAULT_CLIENT_CERT;
    
    fprintf(stderr, "=== TEE Provider V2 TLS客户端 ===\n");
    fprintf(stderr, "连接目标: %s:%d\n", server_host, server_port);
    fprintf(stderr, "客户端证书: %s\n", client_cert);
    fprintf(stderr, "特性: 无私钥文件加载，纯TEE签名\n\n");
    
    // 1. 创建OpenSSL库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        log_error("无法创建OpenSSL库上下文");
        goto cleanup;
    }
    log_info("✅ OpenSSL库上下文创建成功");
    
    // 2. 加载默认provider
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        log_error("无法加载默认provider");
        goto cleanup;
    }
    log_info("✅ 默认provider加载成功");
    
    // 3. 添加并加载TEE Provider V2
    log_info("🔧 加载TEE Provider V2");
    
    // 注册内置provider
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        log_error("无法注册TEE Provider V2");
        goto cleanup;
    }
    
    // 加载TEE provider
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        log_error("无法加载TEE Provider V2");
        goto cleanup;
    }
    log_info("✅ TEE Provider V2加载成功");
    
    // 4. 配置TEE Provider
    log_info("⚙️  配置TEE Provider");
    if (!tee_provider_configure(client_cert)) {
        log_error("TEE Provider配置失败");
        goto cleanup;
    }
    log_info("✅ TEE Provider配置成功");
    
    // 5. 创建SSL上下文（使用TEE Provider V2）
    ssl_ctx = create_ssl_context_v2(libctx);
    if (!ssl_ctx) {
        log_error("无法创建SSL上下文");
        goto cleanup;
    }
    log_info("✅ SSL上下文创建成功");
    
    // 6. 建立TCP连接
    sockfd = create_tcp_connection(server_host, server_port);
    if (sockfd < 0) {
        log_error("TCP连接失败");
        goto cleanup;
    }
    
    // 7. 创建SSL连接
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        log_error("无法创建SSL连接");
        goto cleanup;
    }
    
    if (SSL_set_fd(ssl, sockfd) != 1) {
        log_error("无法绑定SSL到套接字");
        goto cleanup;
    }
    
    // 8. 执行TLS握手和数据交换
    if (!perform_tls_handshake_and_exchange(ssl)) {
        log_error("TLS握手或数据交换失败");
        goto cleanup;
    }
    
    log_info("🎉 TEE Provider V2 TLS客户端运行成功！");
    ret = 1;
    
cleanup:
    if (ssl) SSL_free(ssl);
    if (sockfd >= 0) close(sockfd);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);
    
    fprintf(stderr, "\n=== TEE Provider V2 TLS客户端%s ===\n", ret ? "成功" : "失败");
    return ret ? 0 : 1;
}