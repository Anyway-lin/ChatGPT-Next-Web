# OpenSSL Keyless Mechanism Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
LDFLAGS = -lssl -lcrypto -lpthread

# 源文件
SOURCES = tee_sign.c keyless_ssl.c test_keyless.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = tee_sign.h keyless_ssl.h

# 主要目标
TARGET = test_keyless
DEMO = demo
TLS_DEMO = tls_handshake_demo
SIMPLE_TLS = simple_tls_demo
LIBRARY = libkeyless.so

# 默认目标
all: $(TARGET) $(DEMO) $(TLS_DEMO) $(SIMPLE_TLS) $(LIBRARY)

# 编译测试程序
$(TARGET): $(OBJECTS)
	@echo "Linking test program..."
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Test program built successfully: $(TARGET)"

# 编译演示程序
$(DEMO): demo.o tee_sign.o keyless_ssl.o
	@echo "Linking demo program..."
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Demo program built successfully: $(DEMO)"

# 编译TLS握手演示程序
$(TLS_DEMO): tls_handshake_demo.o tee_sign.o keyless_ssl.o
	@echo "Linking TLS handshake demo program..."
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "TLS demo program built successfully: $(TLS_DEMO)"

# 编译简化TLS演示程序
$(SIMPLE_TLS): simple_tls_demo.o tee_sign.o keyless_ssl.o
	@echo "Linking simple TLS demo program..."
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Simple TLS demo program built successfully: $(SIMPLE_TLS)"

# 编译共享库
$(LIBRARY): tee_sign.o keyless_ssl.o
	@echo "Building shared library..."
	$(CC) -shared -o $@ $^ $(LDFLAGS)
	@echo "Shared library built successfully: $(LIBRARY)"

# 编译目标文件
%.o: %.c $(HEADERS)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# 运行测试
test: $(TARGET)
	@echo "Running keyless SSL tests..."
	./$(TARGET)

# 运行测试（详细输出）
test-verbose: $(TARGET)
	@echo "Running keyless SSL tests with verbose output..."
	LD_LIBRARY_PATH=. ./$(TARGET)

# 运行演示程序
run-demo: $(DEMO)
	@echo "Running keyless SSL demo..."
	./$(DEMO)

# 运行TLS握手演示程序
run-tls-demo: $(TLS_DEMO)
	@echo "Running keyless TLS handshake demo..."
	./$(TLS_DEMO)

# 运行简化TLS演示程序
run-simple-tls: $(SIMPLE_TLS)
	@echo "Running simple keyless TLS demo..."
	./$(SIMPLE_TLS)

# 安装库文件
install: $(LIBRARY)
	@echo "Installing library and headers..."
	sudo cp $(LIBRARY) /usr/local/lib/
	sudo cp $(HEADERS) /usr/local/include/
	sudo ldconfig
	@echo "Installation completed"

# 卸载库文件
uninstall:
	@echo "Uninstalling library and headers..."
	sudo rm -f /usr/local/lib/$(LIBRARY)
	sudo rm -f /usr/local/include/tee_sign.h
	sudo rm -f /usr/local/include/keyless_ssl.h
	sudo ldconfig
	@echo "Uninstallation completed"

# 检查依赖
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists openssl && echo "✓ OpenSSL development libraries found" || echo "✗ OpenSSL development libraries not found"
	@which gcc > /dev/null && echo "✓ GCC compiler found" || echo "✗ GCC compiler not found"
	@echo "Dependencies check completed"

# 清理编译文件
clean:
	@echo "Cleaning build files..."
	rm -f $(OBJECTS) demo.o tls_handshake_demo.o simple_tls_demo.o $(TARGET) $(DEMO) $(TLS_DEMO) $(SIMPLE_TLS) $(LIBRARY)
	rm -f *.so *.a
	@echo "Clean completed"

# 显示帮助信息
help:
	@echo "OpenSSL Keyless Mechanism Build System"
	@echo "Available targets:"
	@echo "  all             - Build all programs and shared library (default)"
	@echo "  test            - Build and run tests"
	@echo "  test-verbose    - Build and run tests with verbose output"
	@echo "  run-demo        - Run basic keyless SSL demo"
	@echo "  run-tls-demo    - Run complete TLS handshake demo"
	@echo "  run-simple-tls  - Run simplified TLS handshake demo"
	@echo "  install         - Install library to system"
	@echo "  uninstall       - Remove library from system"
	@echo "  check-deps      - Check build dependencies"
	@echo "  clean           - Remove build files"
	@echo "  help            - Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make all            # Build everything"
	@echo "  make run-tls-demo   # Run TLS handshake demo"
	@echo "  make test           # Run tests"
	@echo "  make clean          # Clean up"

# 调试构建
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)
	@echo "Debug build completed"

# 发布构建
release: CFLAGS += -O3 -DNDEBUG
release: $(TARGET) $(LIBRARY)
	@echo "Release build completed"

# 代码分析
analyze:
	@echo "Running static analysis..."
	@which cppcheck > /dev/null && cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCES) || echo "cppcheck not found, skipping analysis"

# 内存检查
valgrind: $(TARGET)
	@echo "Running memory leak check..."
	@which valgrind > /dev/null && valgrind --leak-check=full --track-origins=yes ./$(TARGET) || echo "valgrind not found, skipping memory check"

# 显示版本信息
version:
	@echo "OpenSSL Keyless Mechanism v1.0"
	@echo "Built with:"
	@$(CC) --version | head -1
	@pkg-config --modversion openssl 2>/dev/null || echo "OpenSSL version unknown"

.PHONY: all test test-verbose install uninstall check-deps clean help debug release analyze valgrind version