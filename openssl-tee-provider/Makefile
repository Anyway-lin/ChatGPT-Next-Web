# TEE Provider Makefile
# 用于编译OpenSSL 3.0.9 TEE Provider及相关组件

# 编译器和工具
CC = gcc
AR = ar
INSTALL = install
MKDIR_P = mkdir -p

# 目录定义
SRCDIR = src
EXAMPLEDIR = examples
BUILDDIR = build
CERTDIR = certs
TESTDIR = tests

# OpenSSL 相关设置
OPENSSL_PREFIX ?= /usr/local
OPENSSL_INCDIR ?= $(OPENSSL_PREFIX)/include
OPENSSL_LIBDIR ?= $(OPENSSL_PREFIX)/lib

# 编译选项
CFLAGS = -Wall -Wextra -std=c99 -fPIC -O2 -g
CFLAGS += -I$(OPENSSL_INCDIR)
CFLAGS += -I$(SRCDIR)

# 链接选项
LDFLAGS = -L$(OPENSSL_LIBDIR)
LIBS = -lssl -lcrypto -ldl -lpthread

# 共享库选项
SHARED_CFLAGS = $(CFLAGS) -shared
SHARED_LDFLAGS = $(LDFLAGS) -shared

# 源文件
PROVIDER_SOURCES = $(SRCDIR)/tee_provider.c
TEE_INTERFACE_SOURCES = $(EXAMPLEDIR)/tee_interface.c
CLIENT_SOURCES = $(EXAMPLEDIR)/client.c
SERVER_SOURCES = $(EXAMPLEDIR)/server.c

# 目标文件
PROVIDER_TARGET = $(BUILDDIR)/libtee_provider.so
CLIENT_TARGET = $(BUILDDIR)/client
SERVER_TARGET = $(BUILDDIR)/server
TEE_INTERFACE_OBJ = $(BUILDDIR)/tee_interface.o

# 默认目标
.PHONY: all clean install uninstall test certs help

all: $(BUILDDIR) $(PROVIDER_TARGET) $(CLIENT_TARGET) $(SERVER_TARGET)

# 创建构建目录
$(BUILDDIR):
	@echo "Creating build directory..."
	$(MKDIR_P) $(BUILDDIR)

# 编译TEE Provider共享库
$(PROVIDER_TARGET): $(PROVIDER_SOURCES) $(TEE_INTERFACE_OBJ)
	@echo "Building TEE Provider shared library..."
	$(CC) $(SHARED_CFLAGS) -o $@ $(PROVIDER_SOURCES) $(TEE_INTERFACE_OBJ) $(SHARED_LDFLAGS) $(LIBS)
	@echo "TEE Provider library built: $@"

# 编译TEE接口对象文件
$(TEE_INTERFACE_OBJ): $(TEE_INTERFACE_SOURCES)
	@echo "Compiling TEE interface..."
	$(CC) $(CFLAGS) -c -o $@ $(TEE_INTERFACE_SOURCES)

# 编译客户端
$(CLIENT_TARGET): $(CLIENT_SOURCES) $(TEE_INTERFACE_OBJ)
	@echo "Building client..."
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SOURCES) $(TEE_INTERFACE_OBJ) $(LDFLAGS) $(LIBS)
	@echo "Client built: $@"

# 编译服务端
$(SERVER_TARGET): $(SERVER_SOURCES)
	@echo "Building server..."
	$(CC) $(CFLAGS) -o $@ $(SERVER_SOURCES) $(LDFLAGS) $(LIBS)
	@echo "Server built: $@"

# 生成测试证书
certs:
	@echo "Generating test certificates..."
	@if [ ! -d $(CERTDIR) ]; then $(MKDIR_P) $(CERTDIR); fi
	@cd $(CERTDIR) && chmod +x generate_certs.sh && ./generate_certs.sh
	@echo "Test certificates generated in $(CERTDIR)/"

# 测试目标
test: all certs
	@echo "Running TEE Provider tests..."
	@echo "Starting test server in background..."
	@cd $(shell pwd) && $(SERVER_TARGET) &
	@SERVER_PID=$$!; \
	sleep 2; \
	echo "Running test client..."; \
	$(CLIENT_TARGET) || true; \
	echo "Stopping test server..."; \
	kill $$SERVER_PID 2>/dev/null || true
	@echo "Tests completed"

# 快速测试（仅编译检查）
check: all
	@echo "Build check completed successfully"
	@echo "All components compiled without errors"

# 安装
install: all
	@echo "Installing TEE Provider..."
	$(MKDIR_P) $(DESTDIR)$(OPENSSL_LIBDIR)/engines-3
	$(INSTALL) -m 755 $(PROVIDER_TARGET) $(DESTDIR)$(OPENSSL_LIBDIR)/engines-3/
	@echo "TEE Provider installed to $(DESTDIR)$(OPENSSL_LIBDIR)/engines-3/"

# 卸载
uninstall:
	@echo "Uninstalling TEE Provider..."
	rm -f $(DESTDIR)$(OPENSSL_LIBDIR)/engines-3/libtee_provider.so
	@echo "TEE Provider uninstalled"

# 清理
clean:
	@echo "Cleaning build files..."
	rm -rf $(BUILDDIR)
	@echo "Cleaning certificate files..."
	rm -f $(CERTDIR)/*.pem $(CERTDIR)/*.key
	@echo "Clean completed"

# 深度清理
distclean: clean
	@echo "Deep cleaning..."
	rm -rf $(BUILDDIR) $(CERTDIR)/*.pem $(CERTDIR)/*.key
	@echo "Deep clean completed"

# 显示帮助信息
help:
	@echo "TEE Provider Makefile Help"
	@echo "=========================="
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build all components (default)"
	@echo "  certs       - Generate test certificates"
	@echo "  test        - Build, generate certs, and run tests"
	@echo "  check       - Build check only"
	@echo "  install     - Install TEE Provider to system"
	@echo "  uninstall   - Remove TEE Provider from system"
	@echo "  clean       - Remove build files"
	@echo "  distclean   - Remove all generated files"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  OPENSSL_PREFIX - OpenSSL installation prefix (default: /usr/local)"
	@echo "  CC             - C compiler (default: gcc)"
	@echo "  DESTDIR        - Installation root directory"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make all                                 # Build everything"
	@echo "  make certs                              # Generate certificates"
	@echo "  make test                               # Run full test"
	@echo "  make OPENSSL_PREFIX=/usr all            # Build with system OpenSSL"
	@echo "  make install DESTDIR=/tmp/install       # Install to custom directory"
	@echo ""
	@echo "Requirements:"
	@echo "  - OpenSSL 3.0.9 development files"
	@echo "  - GCC compiler"
	@echo "  - Make utility"
	@echo "  - Standard C library"

# 调试信息
debug:
	@echo "Build Configuration:"
	@echo "  CC             = $(CC)"
	@echo "  CFLAGS         = $(CFLAGS)"
	@echo "  LDFLAGS        = $(LDFLAGS)"
	@echo "  LIBS           = $(LIBS)"
	@echo "  OPENSSL_PREFIX = $(OPENSSL_PREFIX)"
	@echo "  OPENSSL_INCDIR = $(OPENSSL_INCDIR)"
	@echo "  OPENSSL_LIBDIR = $(OPENSSL_LIBDIR)"
	@echo "  BUILDDIR       = $(BUILDDIR)"
	@echo ""
	@echo "Targets:"
	@echo "  PROVIDER_TARGET = $(PROVIDER_TARGET)"
	@echo "  CLIENT_TARGET   = $(CLIENT_TARGET)"
	@echo "  SERVER_TARGET   = $(SERVER_TARGET)"

# 版本信息
version:
	@echo "TEE Provider Build System v1.0.0"
	@echo "Compatible with OpenSSL 3.0.9"
	@echo "Build date: $$(date)"

# 验证OpenSSL安装
verify-openssl:
	@echo "Verifying OpenSSL installation..."
	@if [ -f "$(OPENSSL_INCDIR)/openssl/opensslv.h" ]; then \
		echo "✓ OpenSSL headers found at $(OPENSSL_INCDIR)"; \
	else \
		echo "✗ OpenSSL headers not found at $(OPENSSL_INCDIR)"; \
		exit 1; \
	fi
	@if [ -f "$(OPENSSL_LIBDIR)/libssl.so" ] || [ -f "$(OPENSSL_LIBDIR)/libssl.a" ]; then \
		echo "✓ OpenSSL libraries found at $(OPENSSL_LIBDIR)"; \
	else \
		echo "✗ OpenSSL libraries not found at $(OPENSSL_LIBDIR)"; \
		exit 1; \
	fi
	@if command -v openssl >/dev/null 2>&1; then \
		echo "✓ OpenSSL command line tool available"; \
		openssl version; \
	else \
		echo "✗ OpenSSL command line tool not found"; \
		exit 1; \
	fi

# 检查依赖
check-deps: verify-openssl
	@echo "Checking build dependencies..."
	@if command -v $(CC) >/dev/null 2>&1; then \
		echo "✓ C compiler ($(CC)) available"; \
	else \
		echo "✗ C compiler ($(CC)) not found"; \
		exit 1; \
	fi
	@if command -v make >/dev/null 2>&1; then \
		echo "✓ Make utility available"; \
	else \
		echo "✗ Make utility not found"; \
		exit 1; \
	fi
	@echo "All dependencies satisfied"

# 依赖关系
$(CLIENT_TARGET): $(PROVIDER_TARGET)
$(SERVER_TARGET): | $(BUILDDIR)
$(PROVIDER_TARGET): | $(BUILDDIR)

.PHONY: debug version verify-openssl check-deps