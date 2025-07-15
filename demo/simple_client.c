#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEFAULT_PORT 8443
#define MAX_BUFFER_SIZE 4096

/**
 * 打印SSL错误
 */
static void print_ssl_errors(const char *context) {
    printf("❌ SSL Error in %s:\n", context);
    ERR_print_errors_fp(stdout);
}

/**
 * 连接到TLS服务器并交互
 */
static int connect_to_server(const char *hostname, int port) {
    int client_fd;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    
    printf("🔗 Connecting to %s:%d...\n", hostname, port);
    
    // 创建socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("❌ Socket creation failed");
        return -1;
    }
    
    // 设置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        printf("❌ Invalid address: %s\n", hostname);
        close(client_fd);
        return -1;
    }
    
    // 连接到服务器
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("❌ Connection failed");
        close(client_fd);
        return -1;
    }
    
    printf("✅ Connected to server\n");
    
    // 创建SSL上下文
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("❌ Failed to create SSL context\n");
        print_ssl_errors("SSL_CTX_new");
        close(client_fd);
        return -1;
    }
    
    // 设置SSL选项（跳过证书验证，因为是自签名证书）
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // 创建SSL连接
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("❌ Failed to create SSL connection\n");
        print_ssl_errors("SSL_new");
        SSL_CTX_free(ctx);
        close(client_fd);
        return -1;
    }
    
    SSL_set_fd(ssl, client_fd);
    
    // 执行SSL握手
    printf("🤝 Performing TLS handshake...\n");
    if (SSL_connect(ssl) <= 0) {
        printf("❌ TLS handshake failed\n");
        print_ssl_errors("SSL_connect");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        return -1;
    }
    
    printf("✅ TLS handshake completed!\n");
    printf("   Protocol: %s\n", SSL_get_version(ssl));
    printf("   Cipher: %s\n", SSL_get_cipher(ssl));
    
    // 获取服务器证书信息
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert) {
        char *subject = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);
        printf("   Server certificate: %s\n", subject ? subject : "Unknown");
        if (subject) OPENSSL_free(subject);
        X509_free(peer_cert);
    }
    
    printf("\n💬 Interactive mode started. Type messages to send to server.\n");
    printf("   Special commands: STATUS, SIGN:data, QUIT\n");
    printf("   Press Ctrl+C to exit\n\n");
    
    // 交互式消息循环
    char buffer[MAX_BUFFER_SIZE];
    fd_set readfds;
    int max_fd = client_fd + 1;
    
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(client_fd, &readfds);
        
        printf("📝 Enter message: ");
        fflush(stdout);
        
        int activity = select(max_fd, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("❌ Select error");
            break;
        }
        
        // 处理用户输入
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                printf("\n📢 EOF received, closing connection\n");
                break;
            }
            
            // 移除换行符
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len-1] == '\n') {
                buffer[len-1] = '\0';
            }
            
            // 检查退出命令
            if (strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0) {
                SSL_write(ssl, "QUIT", 4);
                break;
            }
            
            // 发送消息到服务器
            if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
                printf("❌ Failed to send message\n");
                print_ssl_errors("SSL_write");
                break;
            }
            
            // 接收服务器响应
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("📨 Server response:\n%s\n", buffer);
            } else if (bytes == 0) {
                printf("📢 Server closed connection\n");
                break;
            } else {
                printf("❌ Failed to receive response\n");
                print_ssl_errors("SSL_read");
                break;
            }
        }
        
        // 处理服务器主动发送的消息
        if (FD_ISSET(client_fd, &readfds)) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("📨 Server message:\n%s\n", buffer);
            } else if (bytes == 0) {
                printf("📢 Server closed connection\n");
                break;
            } else {
                // 可能是因为我们刚发送了数据，这里会被触发但没有数据
                continue;
            }
        }
    }
    
    // 清理连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(client_fd);
    
    printf("✅ Connection closed gracefully\n");
    return 0;
}

/**
 * 显示使用帮助
 */
static void show_usage(const char *program) {
    printf("🔗 Simple TLS Client\n");
    printf("====================\n\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Options:\n");
    printf("  -s, --server <hostname>  Server hostname (default: 127.0.0.1)\n");
    printf("  -p, --port <port>        Server port (default: %d)\n", DEFAULT_PORT);
    printf("  --help                   Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s                              # Connect to 127.0.0.1:%d\n", program, DEFAULT_PORT);
    printf("  %s -s localhost -p 8443        # Connect to localhost:8443\n", program);
    printf("  %s -s 192.168.1.100            # Connect to remote server\n", program);
    printf("\n");
    printf("Interactive commands:\n");
    printf("  STATUS      - Get server status\n");
    printf("  SIGN:data   - Test TEE signing with 'data'\n");
    printf("  quit/exit   - Close connection\n");
    printf("  Ctrl+C      - Force exit\n");
    printf("\n");
}

/**
 * 主函数
 */
int main(int argc, char *argv[]) {
    const char *hostname = "127.0.0.1";
    int port = DEFAULT_PORT;
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            show_usage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            hostname = argv[++i];
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (port <= 0 || port > 65535) {
                printf("❌ Invalid port number: %d\n", port);
                return 1;
            }
        } else {
            printf("❌ Unknown option: %s\n", argv[i]);
            show_usage(argv[0]);
            return 1;
        }
    }
    
    printf("🔗 === Simple TLS Client ===\n\n");
    
    return connect_to_server(hostname, port);
}