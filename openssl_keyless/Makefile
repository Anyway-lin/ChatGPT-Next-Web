# OpenSSL Keyless Library Project Makefile
# =====================================

# 编译器和标志
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=c99 -D_GNU_SOURCE
INCLUDES = -I./lib/include
LIBS = -lssl -lcrypto -lpthread

# 目录定义
LIB_SRC_DIR = lib/src
LIB_INCLUDE_DIR = lib/include
DEMO_DIR = demo
SERVER_DIR = server
EXAMPLES_DIR = examples
TESTS_DIR = tests
BUILD_DIR = build

# 源文件
LIB_SOURCES = $(wildcard $(LIB_SRC_DIR)/*.c)
LIB_OBJECTS = $(LIB_SOURCES:$(LIB_SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# 库文件
LIBRARY = $(BUILD_DIR)/libkeyless.so
STATIC_LIBRARY = $(BUILD_DIR)/libkeyless.a

# 可执行文件
KEYLESS_SERVER = $(BUILD_DIR)/keyless_tls_server
SIMPLE_CLIENT = $(BUILD_DIR)/simple_client
KEYLESS_DEMO = $(BUILD_DIR)/keyless_demo

# 测试程序
TEST_PROGRAMS = $(wildcard $(TESTS_DIR)/*.c)
TEST_EXECUTABLES = $(TEST_PROGRAMS:$(TESTS_DIR)/%.c=$(BUILD_DIR)/%)

# 示例程序
EXAMPLE_PROGRAMS = $(wildcard $(EXAMPLES_DIR)/*.c)
EXAMPLE_EXECUTABLES = $(EXAMPLE_PROGRAMS:$(EXAMPLES_DIR)/%.c=$(BUILD_DIR)/%)

# 默认目标
all: check-deps setup-dirs $(LIBRARY) $(STATIC_LIBRARY) $(KEYLESS_SERVER) $(SIMPLE_CLIENT) $(KEYLESS_DEMO) $(TEST_EXECUTABLES) $(EXAMPLE_EXECUTABLES)

# 检查依赖
check-deps:
	@echo "🔍 Checking dependencies..."
	@which gcc > /dev/null || (echo "❌ GCC not found. Please install gcc." && exit 1)
	@pkg-config --exists openssl || (echo "❌ OpenSSL development libraries not found. Please install libssl-dev." && exit 1)
	@echo "✅ Dependencies check passed"

# 创建目录结构
setup-dirs:
	@mkdir -p $(BUILD_DIR)
	@echo "📁 Build directories created"

# 构建共享库
$(LIBRARY): $(LIB_OBJECTS)
	@echo "🔨 Building shared library: $@"
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $^ $(LIBS)
	@echo "✅ Shared library built successfully"

# 构建静态库
$(STATIC_LIBRARY): $(LIB_OBJECTS)
	@echo "🔨 Building static library: $@"
	ar rcs $@ $^
	@echo "✅ Static library built successfully"

# 构建库对象文件
$(BUILD_DIR)/%.o: $(LIB_SRC_DIR)/%.c
	@echo "🔨 Compiling library source: $<"
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

# 构建服务器程序
$(KEYLESS_SERVER): $(SERVER_DIR)/keyless_tls_server.c $(LIBRARY)
	@echo "🔨 Building keyless TLS server: $@"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L$(BUILD_DIR) -lkeyless $(LIBS)
	@echo "✅ Keyless TLS server built successfully"

# 构建客户端程序
$(SIMPLE_CLIENT): $(DEMO_DIR)/simple_client.c
	@echo "🔨 Building simple client: $@"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)
	@echo "✅ Simple client built successfully"

# 构建演示程序
$(KEYLESS_DEMO): $(DEMO_DIR)/keyless_demo.c $(LIBRARY)
	@echo "🔨 Building keyless demo: $@"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L$(BUILD_DIR) -lkeyless $(LIBS)
	@echo "✅ Keyless demo built successfully"

# 构建测试程序
$(BUILD_DIR)/%: $(TESTS_DIR)/%.c $(LIBRARY)
	@echo "🔨 Building test program: $@"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L$(BUILD_DIR) -lkeyless $(LIBS)

# 构建示例程序
$(BUILD_DIR)/%: $(EXAMPLES_DIR)/%.c $(LIBRARY)
	@echo "🔨 Building example program: $@"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L$(BUILD_DIR) -lkeyless $(LIBS)

# ============= 运行目标 =============

# 运行服务器
run-server: $(KEYLESS_SERVER)
	@echo ""
	@echo "🚀 Starting Keyless TLS Server..."
	@echo "================================="
	@echo "🔑 This server demonstrates the keyless SSL/TLS mechanism"
	@echo "🛡️  Private keys are secured in TEE environment"
	@echo ""
	LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH ./$(KEYLESS_SERVER)

# 运行服务器（后台模式）
run-server-bg: $(KEYLESS_SERVER)
	@echo "🚀 Starting Keyless TLS Server in background..."
	LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH ./$(KEYLESS_SERVER) &
	@echo "✅ Server started in background (PID: $$!)"
	@echo "💡 Use 'make stop-server' to stop it"

# 停止后台服务器
stop-server:
	@echo "🛑 Stopping keyless TLS server..."
	@pkill -f keyless_tls_server || echo "No server process found"

# 运行客户端
run-client: $(SIMPLE_CLIENT)
	@echo ""
	@echo "🔗 Starting Simple TLS Client..."
	@echo "==============================="
	@echo "🔗 This client connects to the keyless TLS server"
	@echo "💬 Interactive mode allows testing various commands"
	@echo ""
	./$(SIMPLE_CLIENT)

# 运行演示
run-demo: $(KEYLESS_DEMO)
	@echo ""
	@echo "🎭 Running Keyless SSL Demo..."
	@echo "=============================="
	@echo "🔐 This demo shows complete keyless TLS communication"
	@echo ""
	LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH ./$(KEYLESS_DEMO)

# 运行所有测试
test: $(TEST_EXECUTABLES)
	@echo ""
	@echo "🧪 Running All Tests..."
	@echo "======================"
	@for test_prog in $(TEST_EXECUTABLES); do \
		echo "🔬 Running $$test_prog..."; \
		LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH $$test_prog || exit 1; \
		echo ""; \
	done
	@echo "✅ All tests completed successfully!"

# ============= 分析工具 =============

# Valgrind内存检查
valgrind-server: $(KEYLESS_SERVER)
	@echo "🔍 Running server with Valgrind memory check..."
	LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH valgrind --leak-check=full --show-leak-kinds=all ./$(KEYLESS_SERVER)

valgrind-demo: $(KEYLESS_DEMO)
	@echo "🔍 Running demo with Valgrind memory check..."
	LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH valgrind --leak-check=full --show-leak-kinds=all ./$(KEYLESS_DEMO)

# 静态代码分析
static-analysis:
	@echo "🔍 Running static code analysis..."
	@which cppcheck > /dev/null && cppcheck --enable=all --std=c99 $(LIB_SRC_DIR)/*.c $(SERVER_DIR)/*.c $(DEMO_DIR)/*.c || echo "cppcheck not found, skipping analysis"

# 性能基准测试
benchmark: $(TEST_EXECUTABLES)
	@echo "📊 Running performance benchmark..."
	@for test_prog in $(TEST_EXECUTABLES); do \
		echo "⏱️  Benchmarking $$test_prog..."; \
		LD_LIBRARY_PATH=$(BUILD_DIR):$$LD_LIBRARY_PATH time $$test_prog; \
	done

# ============= 安装和清理 =============

# 系统安装
install: $(LIBRARY) $(STATIC_LIBRARY)
	@echo "📦 Installing keyless library system-wide..."
	sudo mkdir -p /usr/local/lib /usr/local/include/keyless
	sudo cp $(LIBRARY) $(STATIC_LIBRARY) /usr/local/lib/
	sudo cp $(LIB_INCLUDE_DIR)/*.h /usr/local/include/keyless/
	sudo ldconfig
	@echo "✅ Installation completed"
	@echo "💡 Include path: /usr/local/include/keyless/"
	@echo "💡 Library path: /usr/local/lib/"

# 卸载
uninstall:
	@echo "🗑️  Uninstalling keyless library..."
	sudo rm -f /usr/local/lib/libkeyless.so /usr/local/lib/libkeyless.a
	sudo rm -rf /usr/local/include/keyless/
	sudo ldconfig
	@echo "✅ Uninstall completed"

# 清理构建文件
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "✅ Clean completed"

# 深度清理（包括临时文件）
distclean: clean
	@echo "🧹 Deep cleaning..."
	find . -name "*.o" -delete
	find . -name "*.so" -delete
	find . -name "*.a" -delete
	find . -name "*~" -delete
	find . -name "core" -delete
	@echo "✅ Deep clean completed"

# ============= 开发工具 =============

# 代码格式化
format:
	@echo "🎨 Formatting code..."
	@which clang-format > /dev/null && \
		find $(LIB_SRC_DIR) $(LIB_INCLUDE_DIR) $(SERVER_DIR) $(DEMO_DIR) -name "*.c" -o -name "*.h" | \
		xargs clang-format -i || echo "clang-format not found, skipping formatting"
	@echo "✅ Code formatting completed"

# 生成文档
docs:
	@echo "📚 Generating documentation..."
	@which doxygen > /dev/null && doxygen Doxyfile || echo "Doxygen not found, skipping documentation generation"

# 项目信息
info:
	@echo "📋 Project Information"
	@echo "====================="
	@echo "Project: OpenSSL Keyless Library"
	@echo "Version: 1.0.0"
	@echo "Author: Security Team"
	@echo ""
	@echo "📁 Directory Structure:"
	@echo "  lib/include/    - Library headers"
	@echo "  lib/src/        - Library source code"
	@echo "  server/         - TLS server application"
	@echo "  demo/           - Demo applications"
	@echo "  examples/       - Example programs"
	@echo "  tests/          - Test suite"
	@echo "  build/          - Build artifacts"
	@echo ""
	@echo "🔧 Available Targets:"
	@echo "  make all        - Build everything"
	@echo "  make run-server - Start keyless TLS server"
	@echo "  make run-client - Start interactive client"
	@echo "  make run-demo   - Run complete demo"
	@echo "  make test       - Run all tests"
	@echo ""

# 展示使用示例
examples:
	@echo "💡 Usage Examples"
	@echo "================"
	@echo ""
	@echo "🔐 Basic Server-Client Demo:"
	@echo "  Terminal 1: make run-server"
	@echo "  Terminal 2: make run-client"
	@echo ""
	@echo "🎭 Complete Demonstration:"
	@echo "  make run-demo"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test"
	@echo ""
	@echo "📦 Installation:"
	@echo "  make install"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make static-analysis"
	@echo "  make valgrind-server"
	@echo "  make format"
	@echo ""

# 帮助
help:
	@echo "🔐 OpenSSL Keyless Library Build System"
	@echo "========================================"
	@echo ""
	@echo "📖 Quick Start:"
	@echo "  make all                    # Build everything"
	@echo "  make examples               # Show usage examples"
	@echo "  make info                   # Project information"
	@echo ""
	@echo "🏗️  Build Targets:"
	@echo "  all                         # Build all components"
	@echo "  $(LIBRARY)       # Build shared library"
	@echo "  $(STATIC_LIBRARY)  # Build static library"
	@echo "  $(KEYLESS_SERVER)     # Build TLS server"
	@echo "  $(SIMPLE_CLIENT)      # Build TLS client"
	@echo ""
	@echo "🚀 Run Targets:"
	@echo "  run-server                  # Start keyless TLS server"
	@echo "  run-client                  # Start interactive client"
	@echo "  run-demo                    # Run complete demo"
	@echo "  test                        # Run all tests"
	@echo ""
	@echo "🔧 Analysis:"
	@echo "  valgrind-server             # Memory check server"
	@echo "  valgrind-demo               # Memory check demo"
	@echo "  static-analysis             # Static code analysis"
	@echo "  benchmark                   # Performance testing"
	@echo ""
	@echo "📦 Installation:"
	@echo "  install                     # Install system-wide"
	@echo "  uninstall                   # Remove from system"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  clean                       # Clean build files"
	@echo "  distclean                   # Deep clean"
	@echo ""
	@echo "🛠️  Development:"
	@echo "  format                      # Format code"
	@echo "  docs                        # Generate documentation"
	@echo ""

# Phony目标
.PHONY: all check-deps setup-dirs clean distclean install uninstall \
        run-server run-server-bg stop-server run-client run-demo test \
        valgrind-server valgrind-demo static-analysis benchmark \
        format docs info examples help

# 依赖关系
$(LIB_OBJECTS): | setup-dirs
$(KEYLESS_SERVER): $(LIBRARY)
$(KEYLESS_DEMO): $(LIBRARY)
$(TEST_EXECUTABLES): $(LIBRARY)
$(EXAMPLE_EXECUTABLES): $(LIBRARY)