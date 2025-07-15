# Keyless TLS Demo Makefile

CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -std=c99
LDFLAGS = -lssl -lcrypto -lpthread

# 源文件目录
SRC_DIR = src
CERT_DIR = certs
SCRIPT_DIR = scripts

# 目标文件
TARGETS = tls_server tls_client test_tee

# 源文件
TEE_MOCK_SRC = $(SRC_DIR)/tee_mock.c
KEYLESS_PROVIDER_SRC = $(SRC_DIR)/keyless_provider.c
TLS_SERVER_SRC = $(SRC_DIR)/tls_server.c
TLS_CLIENT_SRC = $(SRC_DIR)/tls_client.c
TEST_TEE_SRC = $(SRC_DIR)/test_tee.c

# 头文件依赖
TEE_MOCK_H = $(SRC_DIR)/tee_mock.h
KEYLESS_PROVIDER_H = $(SRC_DIR)/keyless_provider.h

.PHONY: all clean certs test install-deps help

all: certs $(TARGETS)

# 检查并安装依赖
check-deps:
	@echo "Checking OpenSSL development libraries..."
	@pkg-config --exists openssl || (echo "Error: OpenSSL development libraries not found. Please install libssl-dev" && exit 1)
	@echo "OpenSSL version: $$(pkg-config --modversion openssl)"

# 安装依赖（Ubuntu/Debian）
install-deps:
	@echo "Installing dependencies for Ubuntu/Debian..."
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev pkg-config

# 生成证书
certs:
	@echo "Generating certificates..."
	@mkdir -p $(CERT_DIR)
	@cd $(SCRIPT_DIR) && chmod +x generate_certs.sh && ./generate_certs.sh

# 编译TEE模拟库
$(SRC_DIR)/tee_mock.o: $(TEE_MOCK_SRC) $(TEE_MOCK_H)
	$(CC) $(CFLAGS) -c $< -o $@

# 编译Keyless Provider
$(SRC_DIR)/keyless_provider.o: $(KEYLESS_PROVIDER_SRC) $(KEYLESS_PROVIDER_H) $(TEE_MOCK_H)
	$(CC) $(CFLAGS) -c $< -o $@

# 编译TLS服务器
tls_server: $(TLS_SERVER_SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# 编译TLS客户端（使用keyless provider）
tls_client: $(TLS_CLIENT_SRC) $(SRC_DIR)/tee_mock.o $(SRC_DIR)/keyless_provider.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 编译TEE测试程序
test_tee: $(TEST_TEE_SRC) $(SRC_DIR)/tee_mock.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 运行基本测试
test: test_tee
	@echo "Running TEE mock tests..."
	./test_tee

# 运行完整的TLS测试
test-tls: all
	@echo "Starting TLS server in background..."
	@./tls_server &
	@SERVER_PID=$$!; \
	sleep 2; \
	echo "Running TLS client test..."; \
	./tls_client && echo "TLS test completed successfully" || echo "TLS test failed"; \
	echo "Stopping TLS server..."; \
	kill $$SERVER_PID 2>/dev/null || true

# 运行交互式测试
demo: all
	@echo "=== Keyless TLS Demo ==="
	@echo "1. Start the server in one terminal:"
	@echo "   ./tls_server"
	@echo ""
	@echo "2. Run the client in another terminal:"
	@echo "   ./tls_client"
	@echo ""
	@echo "Files generated:"
	@echo "   - TLS Server: ./tls_server"
	@echo "   - TLS Client: ./tls_client"
	@echo "   - TEE Test: ./test_tee"
	@echo ""
	@echo "Certificates are in the 'certs/' directory"

# 清理编译文件
clean:
	rm -f $(TARGETS)
	rm -f $(SRC_DIR)/*.o
	rm -f core *.core

# 完全清理（包括证书）
distclean: clean
	rm -rf $(CERT_DIR)

# 显示帮助信息
help:
	@echo "Keyless TLS Demo - Available targets:"
	@echo ""
	@echo "  all          - Build all targets (default)"
	@echo "  certs        - Generate test certificates"
	@echo "  test         - Run TEE mock tests"
	@echo "  test-tls     - Run automated TLS test"
	@echo "  demo         - Show demo instructions"
	@echo "  install-deps - Install required dependencies (Ubuntu/Debian)"
	@echo "  check-deps   - Check if dependencies are installed"
	@echo "  clean        - Remove compiled files"
	@echo "  distclean    - Remove compiled files and certificates"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Individual targets:"
	@echo "  tls_server   - Build TLS server"
	@echo "  tls_client   - Build keyless TLS client"
	@echo "  test_tee     - Build TEE test program"
	@echo ""
	@echo "Usage examples:"
	@echo "  make install-deps  # Install dependencies"
	@echo "  make all          # Build everything"
	@echo "  make test         # Run tests"
	@echo "  make demo         # Show demo instructions"

# 添加依赖关系
$(SRC_DIR)/keyless_provider.o: $(TEE_MOCK_H)
tls_client: $(TEE_MOCK_H) $(KEYLESS_PROVIDER_H)