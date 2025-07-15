#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* 声明TEE Provider加载函数 */
extern int tee_provider_load_private_key(const char *key_file);
extern void tee_provider_cleanup(void);

/* 错误处理 */
static void handle_openssl_error(const char *msg) {
    fprintf(stderr, "OpenSSL Error in %s:\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* 创建TCP连接 */
static int create_tcp_connection(const char *host, int port) {
    int sockfd;
    struct sockaddr_in addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connection failed");
        close(sockfd);
        return -1;
    }
    
    printf("TCP连接建立成功 %s:%d\n", host, port);
    return sockfd;
}

/* 加载证书链 */
static int load_certificate_chain(SSL_CTX *ctx, const char *cert_file) {
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) {
        fprintf(stderr, "Error: 无法加载证书链文件 %s\n", cert_file);
        return 0;
    }
    
    printf("证书链加载成功: %s\n", cert_file);
    return 1;
}

/* 设置CA证书验证 */
static int setup_ca_verification(SSL_CTX *ctx, const char *ca_file) {
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        fprintf(stderr, "Error: 无法加载CA证书 %s\n", ca_file);
        return 0;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("CA证书验证设置成功: %s\n", ca_file);
    return 1;
}

/* TLS客户端主函数 */
int main(int argc, char *argv[]) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    OSSL_PROVIDER *tee_provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    int sockfd = -1;
    int ret = 1;
    char buffer[4096];
    int bytes;
    
    /* 参数检查 */
    if (argc != 6) {
        fprintf(stderr, "用法: %s <服务器IP> <端口> <设备私钥文件> <设备证书链文件> <CA证书文件>\n", argv[0]);
        fprintf(stderr, "示例: %s 127.0.0.1 8443 certs/device-key-nopass.pem certs/device-chain.pem certs/ca-cert.pem\n", argv[0]);
        return 1;
    }
    
    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    const char *device_key_file = argv[3];
    const char *device_cert_file = argv[4];
    const char *ca_cert_file = argv[5];
    
    printf("=== TLS客户端启动 ===\n");
    printf("服务器: %s:%d\n", server_ip, server_port);
    printf("设备私钥: %s\n", device_key_file);
    printf("设备证书链: %s\n", device_cert_file);
    printf("CA证书: %s\n", ca_cert_file);
    
    /* 初始化OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /* 加载Provider */
    printf("\n=== 加载Provider ===\n");
    
    /* 加载默认Provider */
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        fprintf(stderr, "Error: 无法加载默认Provider\n");
        goto cleanup;
    }
    printf("默认Provider加载成功\n");
    
    /* 加载TEE Provider */
    tee_provider = OSSL_PROVIDER_load(NULL, "./build/libtee_provider.so");
    if (!tee_provider) {
        fprintf(stderr, "Error: 无法加载TEE Provider\n");
        fprintf(stderr, "请确保已编译TEE Provider: ./build/libtee_provider.so\n");
        goto cleanup;
    }
    printf("TEE Provider加载成功\n");
    
    /* 加载设备私钥到TEE Provider */
    if (!tee_provider_load_private_key(device_key_file)) {
        fprintf(stderr, "Error: 无法将私钥加载到TEE Provider\n");
        goto cleanup;
    }
    
    /* 创建SSL上下文 */
    printf("\n=== 创建SSL上下文 ===\n");
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        handle_openssl_error("SSL_CTX_new");
    }
    
    /* 设置最小TLS版本 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    /* 加载设备证书链 */
    if (!load_certificate_chain(ctx, device_cert_file)) {
        goto cleanup;
    }
    
    /* 设置CA证书验证 */
    if (!setup_ca_verification(ctx, ca_cert_file)) {
        goto cleanup;
    }
    
    /* 这里是关键：不设置私钥文件，而是依赖TEE Provider */
    printf("使用TEE Provider进行私钥操作（不直接加载私钥文件）\n");
    
    /* 创建TCP连接 */
    printf("\n=== 建立TCP连接 ===\n");
    sockfd = create_tcp_connection(server_ip, server_port);
    if (sockfd < 0) {
        goto cleanup;
    }
    
    /* 创建SSL连接 */
    printf("\n=== 建立TLS连接 ===\n");
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_openssl_error("SSL_new");
    }
    
    /* 绑定socket */
    if (SSL_set_fd(ssl, sockfd) != 1) {
        handle_openssl_error("SSL_set_fd");
    }
    
    /* 设置SNI */
    if (SSL_set_tlsext_host_name(ssl, "localhost") != 1) {
        handle_openssl_error("SSL_set_tlsext_host_name");
    }
    
    /* 执行TLS握手 */
    printf("开始TLS握手...\n");
    int ssl_ret = SSL_connect(ssl);
    if (ssl_ret != 1) {
        int ssl_error = SSL_get_error(ssl, ssl_ret);
        fprintf(stderr, "TLS握手失败 (返回值: %d, 错误码: %d)\n", ssl_ret, ssl_error);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("✓ TLS握手成功！\n");
    
    /* 显示连接信息 */
    printf("\n=== TLS连接信息 ===\n");
    printf("TLS版本: %s\n", SSL_get_version(ssl));
    printf("加密套件: %s\n", SSL_get_cipher(ssl));
    
    /* 验证服务器证书 */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        printf("服务器证书验证: ");
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result == X509_V_OK) {
            printf("✓ 验证成功\n");
        } else {
            printf("✗ 验证失败 (错误码: %ld)\n", verify_result);
        }
        
        /* 显示服务器证书信息 */
        char *subject = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        printf("服务器证书主题: %s\n", subject);
        printf("服务器证书颁发者: %s\n", issuer);
        
        OPENSSL_free(subject);
        OPENSSL_free(issuer);
        X509_free(server_cert);
    }
    
    /* 发送测试数据 */
    printf("\n=== 数据传输测试 ===\n");
    const char *test_message = "Hello from TEE Provider TLS Client!";
    printf("发送数据: %s\n", test_message);
    
    bytes = SSL_write(ssl, test_message, strlen(test_message));
    if (bytes <= 0) {
        fprintf(stderr, "SSL_write失败\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("发送成功，字节数: %d\n", bytes);
    
    /* 接收服务器响应 */
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("接收数据: %s\n", buffer);
    } else {
        printf("没有接收到服务器响应\n");
    }
    
    printf("\n✓ TLS客户端测试成功完成！\n");
    ret = 0;
    
cleanup:
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
    
    /* 清理Provider */
    if (tee_provider) {
        tee_provider_cleanup();
        OSSL_PROVIDER_unload(tee_provider);
    }
    if (default_provider) {
        OSSL_PROVIDER_unload(default_provider);
    }
    
    EVP_cleanup();
    ERR_free_strings();
    
    return ret;
}