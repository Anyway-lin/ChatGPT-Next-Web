# OpenSSL TEE Provider TLS项目 Makefile

CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g -O2
LDFLAGS = -shared

# OpenSSL相关配置
OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl 2>/dev/null || echo "-I/usr/include/openssl")
OPENSSL_LIBS = $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# 目录配置
SRC_DIR = src
BUILD_DIR = build
CERTS_DIR = certs

# 目标文件
PROVIDER_SO = $(BUILD_DIR)/libtee_provider.so
CLIENT_BIN = $(BUILD_DIR)/tls_client
CLIENT_SIMPLE_BIN = $(BUILD_DIR)/tls_client_simple
SERVER_BIN = $(BUILD_DIR)/tls_server

# 源文件
PROVIDER_SRC = $(SRC_DIR)/tee_provider.c
PROVIDER_SIMPLE_SRC = $(SRC_DIR)/tee_provider_simple.c
CLIENT_SRC = $(SRC_DIR)/tls_client.c
CLIENT_SIMPLE_SRC = $(SRC_DIR)/tls_client_simple.c
SERVER_SRC = $(SRC_DIR)/tls_server.c

.PHONY: all clean provider client server certs test install help

# 默认目标
all: simple

# 完整版本（需要完整的OpenSSL开发包）
full: provider client server

# 简化版本（兼容性更好）
simple: client-simple server

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 编译TEE Provider
provider: $(PROVIDER_SO)

$(PROVIDER_SO): $(PROVIDER_SRC) | $(BUILD_DIR)
	@echo "=== 编译TEE Provider ==="
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(LDFLAGS) -o $@ $< $(OPENSSL_LIBS)
	@echo "✓ TEE Provider编译完成: $@"

# 编译TLS客户端
client: $(CLIENT_BIN)

$(CLIENT_BIN): $(CLIENT_SRC) $(PROVIDER_SO) | $(BUILD_DIR)
	@echo "=== 编译TLS客户端 ==="
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LIBS) -ldl
	@echo "✓ TLS客户端编译完成: $@"

# 编译简化版TLS客户端
client-simple: $(CLIENT_SIMPLE_BIN)

$(CLIENT_SIMPLE_BIN): $(CLIENT_SIMPLE_SRC) $(PROVIDER_SIMPLE_SRC) | $(BUILD_DIR)
	@echo "=== 编译简化版TLS客户端 ==="
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(CLIENT_SIMPLE_SRC) $(PROVIDER_SIMPLE_SRC) $(OPENSSL_LIBS)
	@echo "✓ 简化版TLS客户端编译完成: $@"

# 编译TLS服务器
server: $(SERVER_BIN)

$(SERVER_BIN): $(SERVER_SRC) | $(BUILD_DIR)
	@echo "=== 编译TLS服务器 ==="
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LIBS)
	@echo "✓ TLS服务器编译完成: $@"

# 生成证书
certs:
	@echo "=== 生成测试证书 ==="
	cd scripts && chmod +x generate_simple_certs.sh && ./generate_simple_certs.sh
	@echo "✓ 证书生成完成"

# 清理构建文件
clean:
	@echo "=== 清理构建文件 ==="
	rm -rf $(BUILD_DIR)
	@echo "✓ 构建文件清理完成"

# 清理证书文件
clean-certs:
	@echo "=== 清理证书文件 ==="
	rm -rf $(CERTS_DIR)/*.pem $(CERTS_DIR)/*.key $(CERTS_DIR)/*.crt $(CERTS_DIR)/*.csr $(CERTS_DIR)/*.ext $(CERTS_DIR)/*.srl
	@echo "✓ 证书文件清理完成"

# 完全清理
clean-all: clean clean-certs

# 安装依赖（Ubuntu/Debian）
install-deps:
	@echo "=== 安装依赖包 ==="
	sudo apt-get update
	sudo apt-get install -y build-essential pkg-config libssl-dev openssl
	@echo "✓ 依赖包安装完成"

# 检查环境
check-env:
	@echo "=== 检查编译环境 ==="
	@echo "OpenSSL版本:"
	@openssl version
	@echo ""
	@echo "pkg-config OpenSSL配置:"
	@pkg-config --cflags --libs openssl 2>/dev/null || echo "pkg-config未找到openssl，使用默认配置: -lssl -lcrypto"
	@echo ""
	@echo "实际使用的配置:"
	@echo "CFLAGS: $(OPENSSL_CFLAGS)"
	@echo "LIBS: $(OPENSSL_LIBS)"
	@echo ""
	@echo "编译器版本:"
	@$(CC) --version | head -1
	@echo "✓ 环境检查完成"

# 运行测试
test: all certs
	@echo "=== 运行完整测试 ==="
	@echo "请在两个终端中分别运行:"
	@echo "终端1 (服务器): ./$(SERVER_BIN) 8443 certs/server-cert.pem certs/server-key-nopass.pem"
	@echo "终端2 (客户端): ./$(CLIENT_BIN) 127.0.0.1 8443 certs/device-key-nopass.pem certs/device-chain.pem certs/ca-cert.pem"

# 快速测试服务器
test-server: all certs
	@echo "=== 启动测试服务器 ==="
	./$(SERVER_BIN) 8443 certs/server-cert.pem certs/server-key-nopass.pem

# 快速测试客户端
test-client: all
	@echo "=== 启动测试客户端 ==="
	@if [ ! -f certs/ca-cert.pem ]; then \
		echo "Error: 证书文件不存在，请先运行 'make certs'"; \
		exit 1; \
	fi
	./$(CLIENT_SIMPLE_BIN) 127.0.0.1 8443 certs/device-key-nopass.pem certs/device-chain.pem certs/ca-cert.pem

# 显示帮助信息
help:
	@echo "OpenSSL TEE Provider TLS项目 - 可用命令:"
	@echo ""
	@echo "构建命令:"
	@echo "  make all          - 编译简化版本（推荐）"
	@echo "  make simple       - 编译简化版本（兼容性更好）"
	@echo "  make full         - 编译完整版本（需要完整OpenSSL开发包）"
	@echo "  make client-simple- 只编译简化版TLS客户端"
	@echo "  make provider     - 只编译TEE Provider"
	@echo "  make client       - 只编译TLS客户端"
	@echo "  make server       - 只编译TLS服务器"
	@echo ""
	@echo "证书管理:"
	@echo "  make certs        - 生成测试证书"
	@echo "  make clean-certs  - 清理证书文件"
	@echo ""
	@echo "清理命令:"
	@echo "  make clean        - 清理构建文件"
	@echo "  make clean-all    - 清理所有文件（构建文件+证书文件）"
	@echo ""
	@echo "测试命令:"
	@echo "  make test         - 显示测试说明"
	@echo "  make test-server  - 启动测试服务器"
	@echo "  make test-client  - 启动测试客户端"
	@echo ""
	@echo "环境命令:"
	@echo "  make check-env    - 检查编译环境"
	@echo "  make install-deps - 安装依赖包（需要sudo权限）"
	@echo ""
	@echo "帮助:"
	@echo "  make help         - 显示此帮助信息"

# 显示项目状态
status:
	@echo "=== 项目状态 ==="
	@echo "构建文件:"
	@if [ -d $(BUILD_DIR) ]; then \
		ls -la $(BUILD_DIR)/; \
	else \
		echo "  构建目录不存在"; \
	fi
	@echo ""
	@echo "证书文件:"
	@if [ -d $(CERTS_DIR) ]; then \
		ls -la $(CERTS_DIR)/*.pem 2>/dev/null || echo "  没有证书文件"; \
	else \
		echo "  证书目录不存在"; \
	fi