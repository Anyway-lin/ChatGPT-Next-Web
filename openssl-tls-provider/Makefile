# Makefile for OpenSSL TLS Provider Project
# 基于OpenSSL 3.0.9的TEE Provider模型

# 配置
OPENSSL_PREFIX = /usr
CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -fPIC
LDFLAGS = -L$(OPENSSL_PREFIX)/lib/x86_64-linux-gnu -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib
LIBS = -lssl -lcrypto -ldl
INCLUDES = -I$(OPENSSL_PREFIX)/include -Isrc

# 目录
SRC_DIR = src
BUILD_DIR = build
SCRIPTS_DIR = scripts
CERTS_DIR = certs

# 源文件
PROVIDER_SRC = $(SRC_DIR)/tee_provider.c
CLIENT_SRC = $(SRC_DIR)/tls_client.c
SERVER_SRC = $(SRC_DIR)/tls_server.c
TEST_SRC = $(SRC_DIR)/test_tee_signature.c

# 目标文件
PROVIDER_LIB = $(BUILD_DIR)/libtee_provider.so
CLIENT_BIN = $(BUILD_DIR)/tls_client
SERVER_BIN = $(BUILD_DIR)/tls_server
TEST_BIN = $(BUILD_DIR)/test_tee_signature

# 默认目标
all: $(PROVIDER_LIB) $(CLIENT_BIN) $(SERVER_BIN)

# 测试目标（包含签名测试）
test-all: $(PROVIDER_LIB) $(CLIENT_BIN) $(SERVER_BIN) $(TEST_BIN)

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 编译TEE Provider共享库
$(PROVIDER_LIB): $(PROVIDER_SRC) | $(BUILD_DIR)
	@echo "编译TEE Provider共享库..."
	$(CC) $(CFLAGS) $(INCLUDES) -shared -o $@ $< $(LDFLAGS) $(LIBS)
	@echo "TEE Provider编译完成: $@"

# 编译TLS客户端
$(CLIENT_BIN): $(CLIENT_SRC) $(PROVIDER_SRC) | $(BUILD_DIR)
	@echo "编译TLS客户端..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(CLIENT_SRC) $(PROVIDER_SRC) $(LDFLAGS) $(LIBS)
	@echo "TLS客户端编译完成: $@"

# 编译TLS服务器
$(SERVER_BIN): $(SERVER_SRC) | $(BUILD_DIR)
	@echo "编译TLS服务器..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS) $(LIBS)
	@echo "TLS服务器编译完成: $@"

# 编译TEE签名测试程序
$(TEST_BIN): $(TEST_SRC) $(PROVIDER_SRC) | $(BUILD_DIR)
	@echo "编译TEE签名测试程序..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_SRC) $(PROVIDER_SRC) $(LDFLAGS) $(LIBS)
	@echo "TEE签名测试程序编译完成: $@"

# 生成证书
certs: $(SCRIPTS_DIR)/generate_certs.sh
	@echo "生成测试证书..."
	chmod +x $(SCRIPTS_DIR)/generate_certs.sh
	./$(SCRIPTS_DIR)/generate_certs.sh
	@echo "证书生成完成"

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -rf $(BUILD_DIR)
	@echo "构建文件清理完成"

# 清理证书文件
clean-certs:
	@echo "清理证书文件..."
	rm -rf $(CERTS_DIR)
	@echo "证书文件清理完成"

# 完全清理
distclean: clean clean-certs
	@echo "完全清理完成"

# 安装
install: all
	@echo "安装程序..."
	sudo mkdir -p /usr/local/lib
	sudo cp $(PROVIDER_LIB) /usr/local/lib/
	sudo mkdir -p /usr/local/bin
	sudo cp $(CLIENT_BIN) /usr/local/bin/
	sudo cp $(SERVER_BIN) /usr/local/bin/
	sudo ldconfig
	@echo "安装完成"

# 卸载
uninstall:
	@echo "卸载程序..."
	sudo rm -f /usr/local/lib/libtee_provider.so
	sudo rm -f /usr/local/bin/tls_client
	sudo rm -f /usr/local/bin/tls_server
	sudo ldconfig
	@echo "卸载完成"

# 测试
test: all certs
	@echo "运行测试..."
	@echo "启动TLS服务器（后台运行）..."
	./$(SERVER_BIN) -p 4433 &
	@SERVER_PID=$$!; \
	sleep 2; \
	echo "运行TLS客户端测试..."; \
	./$(CLIENT_BIN) -h 127.0.0.1 -p 4433; \
	echo "停止TLS服务器..."; \
	kill $$SERVER_PID 2>/dev/null || true; \
	wait $$SERVER_PID 2>/dev/null || true
	@echo "测试完成"

# 检查环境
check-env:
	@echo "检查编译环境..."
	@if [ ! -d "$(OPENSSL_PREFIX)" ]; then \
		echo "错误: OpenSSL未安装在$(OPENSSL_PREFIX)"; \
		exit 1; \
	fi
	@echo "OpenSSL路径: $(OPENSSL_PREFIX)"
	@$(OPENSSL_PREFIX)/bin/openssl version
	@echo "编译器: $(CC)"
	@$(CC) --version | head -1
	@echo "环境检查完成"

# 帮助
help:
	@echo "可用的make目标:"
	@echo "  all          - 编译所有程序"
	@echo "  certs        - 生成测试证书"
	@echo "  clean        - 清理构建文件"
	@echo "  clean-certs  - 清理证书文件"
	@echo "  distclean    - 完全清理"
	@echo "  install      - 安装程序"
	@echo "  uninstall    - 卸载程序"
	@echo "  test         - 运行测试"
	@echo "  check-env    - 检查编译环境"
	@echo "  help         - 显示此帮助"

# 声明伪目标
.PHONY: all clean clean-certs distclean install uninstall test check-env help certs

# 显示编译进度
.SILENT: