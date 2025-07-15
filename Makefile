# TEE Provider Makefile for OpenSSL 3.0+

# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2 -g
LDFLAGS = -shared

# OpenSSL路径 (可通过环境变量覆盖)
OPENSSL_PREFIX ?= /usr/local
OPENSSL_INCLUDE = $(OPENSSL_PREFIX)/include
OPENSSL_LIB = $(OPENSSL_PREFIX)/lib

# Provider安装路径
PROVIDER_DIR ?= $(OPENSSL_LIB)/ossl-modules

# 使用pkg-config获取OpenSSL配置，如果失败则使用默认路径
PKG_CONFIG_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
PKG_CONFIG_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)

# 包含路径
ifeq ($(PKG_CONFIG_CFLAGS),)
    INCLUDES = -I$(OPENSSL_INCLUDE)
else
    INCLUDES = $(PKG_CONFIG_CFLAGS)
endif

# 链接库
ifeq ($(PKG_CONFIG_LIBS),)
    LIBS = -L$(OPENSSL_LIB) -lcrypto
else
    LIBS = $(PKG_CONFIG_LIBS)
endif

# 源文件和目标文件
SOURCES = tee_provider.c
TARGET = tee_provider.so
OBJECTS = $(SOURCES:.c=.o)

# 默认目标
all: $(TARGET)

# 编译provider
$(TARGET): $(OBJECTS)
	@echo "链接 TEE Provider..."
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "TEE Provider 编译完成: $(TARGET)"

# 编译对象文件
%.o: %.c
	@echo "编译 $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 安装provider
install: $(TARGET)
	@echo "安装 TEE Provider 到 $(PROVIDER_DIR)..."
	@mkdir -p $(PROVIDER_DIR)
	@cp $(TARGET) $(PROVIDER_DIR)/
	@echo "安装完成"

# 清理
clean:
	@echo "清理编译文件..."
	@rm -f $(OBJECTS) $(TARGET)
	@rm -f *.pem *.csr *.crt *.srl
	@echo "清理完成"

# 生成测试证书和密钥
setup-test:
	@echo "设置测试环境..."
	@./setup_test_certs.sh
	@echo "测试环境设置完成"

# 运行基础测试
test: $(TARGET) setup-test
	@echo "运行TEE Provider测试..."
	@./test_tee_provider.sh

# 检查OpenSSL版本
check-openssl:
	@echo "检查OpenSSL版本..."
	@openssl version
	@echo "OpenSSL库路径: $(OPENSSL_LIB)"
	@echo "OpenSSL头文件路径: $(OPENSSL_INCLUDE)"

# 调试构建
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# 帮助信息
help:
	@echo "TEE Provider 构建系统"
	@echo ""
	@echo "可用目标:"
	@echo "  all          - 编译TEE Provider (默认)"
	@echo "  install      - 安装Provider到系统目录"
	@echo "  clean        - 清理编译文件"
	@echo "  setup-test   - 生成测试证书和密钥"
	@echo "  test         - 运行完整测试"
	@echo "  check-openssl- 检查OpenSSL安装"
	@echo "  debug        - 编译调试版本"
	@echo "  help         - 显示此帮助信息"
	@echo ""
	@echo "环境变量:"
	@echo "  OPENSSL_PREFIX  - OpenSSL安装路径 (默认: /usr/local)"
	@echo "  PROVIDER_DIR    - Provider安装目录 (默认: /usr/local/lib/ossl-modules)"
	@echo ""
	@echo "使用示例:"
	@echo "  make"
	@echo "  make install"
	@echo "  make test"

.PHONY: all install clean setup-test test check-openssl debug help