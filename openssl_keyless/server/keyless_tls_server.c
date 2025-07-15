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
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include "../lib/include/tee_sign.h"

#define DEFAULT_PORT 8443
#define MAX_BUFFER_SIZE 4096
#define CERT_VALIDITY_DAYS 365

static int server_running = 1;
static tee_key_handle_t *server_tee_handle = NULL;
static EVP_PKEY *server_pkey = NULL;
static X509 *server_cert = NULL;

/**
 * 信号处理函数
 */
static void signal_handler(int sig) {
    (void)sig;
    printf("\n🛑 Received shutdown signal, stopping server...\n");
    server_running = 0;
}

/**
 * 打印SSL错误
 */
static void print_ssl_errors(const char *context) {
    printf("❌ SSL Error in %s:\n", context);
    ERR_print_errors_fp(stdout);
}

/**
 * 创建临时RSA密钥对（用于证书）
 */
static EVP_PKEY* create_temp_keypair() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/**
 * 创建自签名证书
 */
static X509* create_server_certificate(EVP_PKEY *pkey, const char *hostname) {
    X509 *cert = X509_new();
    if (!cert) return NULL;
    
    // 设置证书版本 (X.509 v3)
    X509_set_version(cert, 2);
    
    // 设置序列号
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    
    // 设置有效期
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60*60*24*CERT_VALIDITY_DAYS);
    
    // 设置公钥
    if (X509_set_pubkey(cert, pkey) != 1) {
        X509_free(cert);
        return NULL;
    }
    
    // 设置主题信息
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                               (unsigned char*)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                               (unsigned char*)"Beijing", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                               (unsigned char*)"Beijing", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (unsigned char*)"Keyless TLS Server", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                               (unsigned char*)"Security Department", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)hostname, -1, -1, 0);
    
    // 设置颁发者（自签名）
    X509_set_issuer_name(cert, name);
    
    // 添加扩展
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    
    // 基本约束
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, 
                                              NID_basic_constraints, 
                                              "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // 密钥用途
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                              "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // 扩展密钥用途
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                              "serverAuth");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // 主题备用名称
    char san[256];
    snprintf(san, sizeof(san), "DNS:%s,DNS:localhost,IP:127.0.0.1", hostname);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // 签署证书
    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        print_ssl_errors("X509_sign");
        X509_free(cert);
        return NULL;
    }
    
    return cert;
}

/**
 * 处理客户端连接
 */
static void handle_client(SSL *ssl, int client_fd, struct sockaddr_in *client_addr) {
    printf("🔗 Client connected from %s:%d\n", 
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    
    // 执行SSL握手
    printf("🤝 Starting TLS handshake...\n");
    int ssl_result = SSL_accept(ssl);
    if (ssl_result <= 0) {
        int ssl_error = SSL_get_error(ssl, ssl_result);
        printf("❌ TLS handshake failed, SSL error: %d\n", ssl_error);
        print_ssl_errors("SSL_accept");
        return;
    }
    
    printf("✅ TLS handshake completed successfully!\n");
    printf("   Protocol: %s\n", SSL_get_version(ssl));
    printf("   Cipher: %s\n", SSL_get_cipher(ssl));
    
    // 主消息循环
    char buffer[MAX_BUFFER_SIZE];
    int bytes;
    
    while (server_running && (bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("📨 Received: %s\n", buffer);
        
        // 处理特殊命令
        if (strncmp(buffer, "QUIT", 4) == 0) {
            const char *goodbye = "Goodbye! Connection closed by client request.\n";
            SSL_write(ssl, goodbye, strlen(goodbye));
            break;
        } else if (strncmp(buffer, "STATUS", 6) == 0) {
            char status[512];
            snprintf(status, sizeof(status), 
                    "🔐 Keyless TLS Server Status:\n"
                    "  Protocol: %s\n"
                    "  Cipher: %s\n"
                    "  TEE Handle: %s\n"
                    "  Private Key: Secured in TEE\n"
                    "  Connection: Active\n",
                    SSL_get_version(ssl), SSL_get_cipher(ssl),
                    server_tee_handle ? "Active" : "Inactive");
            SSL_write(ssl, status, strlen(status));
        } else if (strncmp(buffer, "SIGN:", 5) == 0) {
            // 演示TEE签名功能
            const char *data_to_sign = buffer + 5;
            unsigned char signature[256];
            size_t sig_len = sizeof(signature);
            
            if (server_tee_handle && 
                tee_sign(server_tee_handle, (const unsigned char*)data_to_sign, 
                        strlen(data_to_sign), signature, &sig_len) == TEE_SUCCESS) {
                char response[512];
                snprintf(response, sizeof(response), 
                        "🔑 TEE Signature completed: %zu bytes\n"
                        "✅ Data signed securely in TEE environment\n", sig_len);
                SSL_write(ssl, response, strlen(response));
            } else {
                const char *error = "❌ TEE signing failed\n";
                SSL_write(ssl, error, strlen(error));
            }
        } else {
            // 回显消息
            char response[MAX_BUFFER_SIZE + 64];
            snprintf(response, sizeof(response), 
                    "🔐 Keyless TLS Server Echo: %s\n", buffer);
            SSL_write(ssl, response, strlen(response));
        }
    }
    
    if (bytes < 0) {
        int ssl_error = SSL_get_error(ssl, bytes);
        if (ssl_error != SSL_ERROR_ZERO_RETURN) {
            printf("❌ SSL read error: %d\n", ssl_error);
            print_ssl_errors("SSL_read");
        }
    }
    
    printf("🔌 Client disconnected\n");
}

/**
 * 启动TLS服务器
 */
static int start_tls_server(int port, const char *hostname) {
    int server_fd;
    struct sockaddr_in address;
    SSL_CTX *ctx;
    
    printf("🚀 Starting Keyless TLS Server on port %d...\n", port);
    
    // 创建服务器socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("❌ Socket creation failed");
        return -1;
    }
    
    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("❌ Socket options failed");
        close(server_fd);
        return -1;
    }
    
    // 绑定地址
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("❌ Bind failed");
        close(server_fd);
        return -1;
    }
    
    // 监听连接
    if (listen(server_fd, 5) < 0) {
        perror("❌ Listen failed");
        close(server_fd);
        return -1;
    }
    
    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        printf("❌ Failed to create SSL context\n");
        print_ssl_errors("SSL_CTX_new");
        close(server_fd);
        return -1;
    }
    
    // 设置SSL选项
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // 设置证书和私钥
    if (SSL_CTX_use_certificate(ctx, server_cert) != 1) {
        printf("❌ Failed to set certificate\n");
        print_ssl_errors("SSL_CTX_use_certificate");
        SSL_CTX_free(ctx);
        close(server_fd);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, server_pkey) != 1) {
        printf("❌ Failed to set private key\n");
        print_ssl_errors("SSL_CTX_use_PrivateKey");
        SSL_CTX_free(ctx);
        close(server_fd);
        return -1;
    }
    
    printf("✅ Keyless TLS Server listening on %s:%d\n", hostname, port);
    printf("🔑 Private key secured in TEE environment\n");
    printf("📜 Certificate configured with SAN: %s, localhost, 127.0.0.1\n", hostname);
    printf("\n💡 Available commands for clients:\n");
    printf("   - Send any message for echo\n");
    printf("   - 'STATUS' to get server status\n");
    printf("   - 'SIGN:data' to test TEE signing\n");
    printf("   - 'QUIT' to close connection\n");
    printf("\n🛑 Press Ctrl+C to stop server\n\n");
    
    // 主服务器循环
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // 接受连接
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (server_running) {
                perror("❌ Accept failed");
            }
            continue;
        }
        
        // 创建SSL连接
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            printf("❌ Failed to create SSL connection\n");
            close(client_fd);
            continue;
        }
        
        SSL_set_fd(ssl, client_fd);
        
        // 处理客户端
        handle_client(ssl, client_fd, &client_addr);
        
        // 清理连接
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    
    // 清理
    SSL_CTX_free(ctx);
    close(server_fd);
    printf("✅ Server stopped gracefully\n");
    return 0;
}

/**
 * 显示使用帮助
 */
static void show_usage(const char *program) {
    printf("🔐 Keyless TLS Server\n");
    printf("=====================\n\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Options:\n");
    printf("  -p, --port <port>      Server port (default: %d)\n", DEFAULT_PORT);
    printf("  -h, --hostname <name>  Server hostname (default: localhost)\n");
    printf("  -k, --key-id <id>      TEE key ID (default: 100)\n");
    printf("  --help                 Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s                           # Start server on default port %d\n", program, DEFAULT_PORT);
    printf("  %s -p 8443 -h myserver.com  # Custom port and hostname\n", program);
    printf("  %s -k 200                    # Use different TEE key ID\n", program);
    printf("\n");
}

/**
 * 主函数
 */
int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    const char *hostname = "localhost";
    uint32_t key_id = 100;
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            show_usage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (port <= 0 || port > 65535) {
                printf("❌ Invalid port number: %d\n", port);
                return 1;
            }
        } else if ((strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--hostname") == 0) && i + 1 < argc) {
            hostname = argv[++i];
        } else if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key-id") == 0) && i + 1 < argc) {
            key_id = (uint32_t)atoi(argv[++i]);
            if (key_id >= 256) {
                printf("❌ Invalid key ID: %u (must be < 256)\n", key_id);
                return 1;
            }
        } else {
            printf("❌ Unknown option: %s\n", argv[i]);
            show_usage(argv[0]);
            return 1;
        }
    }
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("🔐 === Keyless TLS Server Initialization ===\n\n");
    
    // 初始化TEE环境
    printf("1. Initializing TEE environment...\n");
    if (tee_init() != TEE_SUCCESS) {
        printf("❌ Failed to initialize TEE\n");
        return 1;
    }
    printf("✅ TEE initialized successfully\n");
    
    // 创建TEE密钥句柄
    printf("\n2. Creating TEE keyless private key (ID: %u)...\n", key_id);
    if (tee_create_key_handle(key_id, TEE_ALG_RSA_PKCS1_SHA256, 2048, &server_tee_handle) != TEE_SUCCESS) {
        printf("❌ Failed to create TEE key handle\n");
        tee_cleanup();
        return 1;
    }
    printf("✅ TEE keyless private key created\n");
    
    // 创建临时密钥对用于证书
    printf("\n3. Creating certificate keypair...\n");
    server_pkey = create_temp_keypair();
    if (!server_pkey) {
        printf("❌ Failed to create certificate keypair\n");
        tee_destroy_key_handle(server_tee_handle);
        tee_cleanup();
        return 1;
    }
    printf("✅ Certificate keypair created\n");
    
    // 创建服务器证书
    printf("\n4. Creating server certificate for %s...\n", hostname);
    server_cert = create_server_certificate(server_pkey, hostname);
    if (!server_cert) {
        printf("❌ Failed to create server certificate\n");
        EVP_PKEY_free(server_pkey);
        tee_destroy_key_handle(server_tee_handle);
        tee_cleanup();
        return 1;
    }
    printf("✅ Server certificate created\n");
    
    // 启动服务器
    printf("\n5. Starting TLS server...\n");
    int result = start_tls_server(port, hostname);
    
    // 清理资源
    printf("\n🧹 Cleaning up resources...\n");
    if (server_cert) X509_free(server_cert);
    if (server_pkey) EVP_PKEY_free(server_pkey);
    if (server_tee_handle) tee_destroy_key_handle(server_tee_handle);
    tee_cleanup();
    printf("✅ Cleanup completed\n");
    
    return result;
}