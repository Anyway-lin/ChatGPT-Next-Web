# OpenSSL Keyless Implementation Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=c99 -D_GNU_SOURCE
INCLUDES = -I.
LIBS = -lssl -lcrypto -lpthread

# Source files
TEE_SOURCES = tee_sign.c
KEYLESS_SOURCES = keyless_ssl.c
ENGINE_SOURCES = keyless_engine.c
DEMO_SOURCES = demo.c
SIMPLE_TLS_SOURCES = simple_tls_demo.c
REAL_KEYLESS_TLS_SOURCES = real_keyless_tls.c
SUCCESSFUL_KEYLESS_TLS_SOURCES = successful_keyless_tls.c
TEST_SOURCES = test_keyless.c
DEBUG_SOURCES = debug_test.c

# Object files
TEE_OBJECTS = $(TEE_SOURCES:.c=.o)
KEYLESS_OBJECTS = $(KEYLESS_SOURCES:.c=.o)
ENGINE_OBJECTS = $(ENGINE_SOURCES:.c=.o)
DEMO_OBJECTS = $(DEMO_SOURCES:.c=.o)
SIMPLE_TLS_OBJECTS = $(SIMPLE_TLS_SOURCES:.c=.o)
REAL_KEYLESS_TLS_OBJECTS = $(REAL_KEYLESS_TLS_SOURCES:.c=.o)
SUCCESSFUL_KEYLESS_TLS_OBJECTS = $(SUCCESSFUL_KEYLESS_TLS_SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
DEBUG_OBJECTS = $(DEBUG_SOURCES:.c=.o)

# Library
LIBRARY = libkeyless.so

# Executables
DEMO_EXEC = demo
SIMPLE_TLS_EXEC = simple_tls_demo
REAL_KEYLESS_TLS_EXEC = real_keyless_tls
SUCCESSFUL_KEYLESS_TLS_EXEC = successful_keyless_tls
TEST_EXEC = test_keyless
DEBUG_EXEC = debug_test

# Default target
all: check-deps $(LIBRARY) $(DEMO_EXEC) $(SIMPLE_TLS_EXEC) $(REAL_KEYLESS_TLS_EXEC) $(SUCCESSFUL_KEYLESS_TLS_EXEC) $(TEST_EXEC) $(DEBUG_EXEC)

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which gcc > /dev/null || (echo "❌ GCC not found. Please install gcc." && exit 1)
	@pkg-config --exists openssl || (echo "❌ OpenSSL development libraries not found. Please install libssl-dev." && exit 1)
	@echo "✅ Dependencies check passed"

# Library target
$(LIBRARY): $(TEE_OBJECTS) $(KEYLESS_OBJECTS) $(ENGINE_OBJECTS)
	@echo "Building shared library $(LIBRARY)..."
	$(CC) -shared -fPIC $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Library built successfully"

# Demo executable
$(DEMO_EXEC): $(DEMO_OBJECTS) $(TEE_OBJECTS) $(KEYLESS_OBJECTS)
	@echo "Building $(DEMO_EXEC)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Demo built successfully"

# Simple TLS demo executable  
$(SIMPLE_TLS_EXEC): $(SIMPLE_TLS_OBJECTS) $(TEE_OBJECTS) $(KEYLESS_OBJECTS)
	@echo "Building $(SIMPLE_TLS_EXEC)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Simple TLS demo built successfully"

# Real keyless TLS demo executable (with ENGINE)
$(REAL_KEYLESS_TLS_EXEC): $(REAL_KEYLESS_TLS_OBJECTS) $(TEE_OBJECTS) $(ENGINE_OBJECTS)
	@echo "Building $(REAL_KEYLESS_TLS_EXEC)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Real keyless TLS demo built successfully"

# Successful keyless TLS demo executable
$(SUCCESSFUL_KEYLESS_TLS_EXEC): $(SUCCESSFUL_KEYLESS_TLS_OBJECTS) $(TEE_OBJECTS)
	@echo "Building $(SUCCESSFUL_KEYLESS_TLS_EXEC)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Successful keyless TLS demo built successfully"

# Test executable
$(TEST_EXEC): $(TEST_OBJECTS) $(TEE_OBJECTS) $(KEYLESS_OBJECTS) $(ENGINE_OBJECTS)
	@echo "Building $(TEST_EXEC)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Test suite built successfully"

# Debug executable
$(DEBUG_EXEC): $(DEBUG_OBJECTS) $(TEE_OBJECTS) $(KEYLESS_OBJECTS) $(ENGINE_OBJECTS)
	@echo "Building $(DEBUG_EXEC)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)
	@echo "✅ Debug test built successfully"

# Object file compilation
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

# Clean
clean:
	@echo "Cleaning up..."
	rm -f *.o $(LIBRARY) $(DEMO_EXEC) $(SIMPLE_TLS_EXEC) $(REAL_KEYLESS_TLS_EXEC) $(TEST_EXEC) $(DEBUG_EXEC)
	@echo "✅ Clean completed"

# Install (for system-wide installation)
install: $(LIBRARY)
	@echo "Installing keyless library..."
	sudo cp $(LIBRARY) /usr/local/lib/
	sudo cp tee_sign.h keyless_ssl.h keyless_engine.h /usr/local/include/
	sudo ldconfig
	@echo "✅ Installation completed"

# Uninstall
uninstall:
	@echo "Uninstalling keyless library..."
	sudo rm -f /usr/local/lib/$(LIBRARY)
	sudo rm -f /usr/local/include/tee_sign.h
	sudo rm -f /usr/local/include/keyless_ssl.h
	sudo rm -f /usr/local/include/keyless_engine.h
	sudo ldconfig
	@echo "✅ Uninstall completed"

# Run basic demo
run-demo: $(DEMO_EXEC)
	@echo ""
	@echo "🚀 Running basic keyless SSL demo..."
	@echo "======================================"
	./$(DEMO_EXEC)

# Run simple TLS demo
run-simple-tls: $(SIMPLE_TLS_EXEC)
	@echo ""
	@echo "🚀 Running simple TLS demo..."
	@echo "=============================="
	./$(SIMPLE_TLS_EXEC)

# Run real keyless TLS demo (with ENGINE)
run-real-keyless-tls: $(REAL_KEYLESS_TLS_EXEC)
	@echo ""
	@echo "🚀 Running REAL keyless TLS demo with ENGINE..."
	@echo "=============================================="
	@echo "This demo will perform a COMPLETE TLS handshake"
	@echo "using ENGINE to intercept OpenSSL signing operations."
	@echo ""
	./$(REAL_KEYLESS_TLS_EXEC)

# Run successful keyless TLS demo
run-successful-keyless-tls: $(SUCCESSFUL_KEYLESS_TLS_EXEC)
	@echo ""
	@echo "🚀 Running SUCCESSFUL keyless TLS demo..."
	@echo "========================================"
	@echo "This demo demonstrates the keyless concept with"
	@echo "TEE integration and successful TLS handshake."
	@echo ""
	./$(SUCCESSFUL_KEYLESS_TLS_EXEC)

# Run tests
test: $(TEST_EXEC)
	@echo ""
	@echo "🧪 Running comprehensive test suite..."
	@echo "====================================="
	./$(TEST_EXEC)

# Run debug test
debug: $(DEBUG_EXEC)
	@echo ""
	@echo "🔍 Running debug test..."
	@echo "======================="
	./$(DEBUG_EXEC)

# Valgrind memory check
valgrind-demo: $(DEMO_EXEC)
	@echo "🔍 Running demo with Valgrind memory check..."
	valgrind --leak-check=full --show-leak-kinds=all ./$(DEMO_EXEC)

valgrind-test: $(TEST_EXEC)
	@echo "🔍 Running tests with Valgrind memory check..."
	valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_EXEC)

valgrind-real-keyless: $(REAL_KEYLESS_TLS_EXEC)
	@echo "🔍 Running real keyless TLS with Valgrind memory check..."
	valgrind --leak-check=full --show-leak-kinds=all ./$(REAL_KEYLESS_TLS_EXEC)

# Static analysis
static-analysis:
	@echo "🔍 Running static analysis..."
	cppcheck --enable=all --std=c99 *.c *.h

# Performance benchmark
benchmark: $(TEST_EXEC)
	@echo "📊 Running performance benchmark..."
	time ./$(TEST_EXEC)

# Code coverage (requires gcov)
coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: LIBS += -lgcov
coverage: clean all test
	@echo "📈 Generating code coverage report..."
	gcov *.c
	@echo "Coverage files generated: *.gcov"

# Format code
format:
	@echo "🎨 Formatting code..."
	@which clang-format > /dev/null && clang-format -i *.c *.h || echo "clang-format not found, skipping formatting"

# Help
help:
	@echo "🔐 OpenSSL Keyless Implementation Build System"
	@echo "============================================="
	@echo ""
	@echo "Available targets:"
	@echo "  all                    - Build all components"
	@echo "  $(LIBRARY)             - Build shared library only"
	@echo "  $(DEMO_EXEC)           - Build basic demo only"
	@echo "  $(SIMPLE_TLS_EXEC)     - Build simple TLS demo only"  
	@echo "  $(REAL_KEYLESS_TLS_EXEC) - Build real keyless TLS demo (ENGINE)"
	@echo "  $(TEST_EXEC)           - Build test suite only"
	@echo "  $(DEBUG_EXEC)          - Build debug test only"
	@echo ""
	@echo "Run targets:"
	@echo "  run-demo               - Run basic keyless SSL demo"
	@echo "  run-simple-tls         - Run simple TLS demo"
	@echo "  run-real-keyless-tls   - Run REAL keyless TLS demo (ENGINE) ⭐"
	@echo "  test                   - Run comprehensive test suite"
	@echo "  debug                  - Run debug test"
	@echo ""
	@echo "Analysis targets:"
	@echo "  valgrind-demo          - Run demo with memory check"
	@echo "  valgrind-test          - Run tests with memory check"
	@echo "  valgrind-real-keyless  - Run real keyless TLS with memory check"
	@echo "  static-analysis        - Run static code analysis"
	@echo "  benchmark              - Run performance benchmark"
	@echo "  coverage               - Generate code coverage report"
	@echo ""
	@echo "Utility targets:"
	@echo "  install                - Install library system-wide"
	@echo "  uninstall              - Remove installed library"
	@echo "  format                 - Format code with clang-format"
	@echo "  clean                  - Clean build artifacts"
	@echo "  check-deps             - Check build dependencies"
	@echo "  help                   - Show this help message"
	@echo ""
	@echo "🎯 RECOMMENDED: 'make run-real-keyless-tls' for complete TLS demo!"
	@echo ""

# Phony targets
.PHONY: all clean install uninstall run-demo run-simple-tls run-real-keyless-tls test debug \
        valgrind-demo valgrind-test valgrind-real-keyless static-analysis benchmark \
        coverage format help check-deps

# Dependencies
$(TEE_OBJECTS): tee_sign.h
$(KEYLESS_OBJECTS): keyless_ssl.h tee_sign.h
$(ENGINE_OBJECTS): keyless_engine.h tee_sign.h
$(DEMO_OBJECTS): tee_sign.h keyless_ssl.h
$(SIMPLE_TLS_OBJECTS): tee_sign.h keyless_ssl.h
$(REAL_KEYLESS_TLS_OBJECTS): keyless_engine.h tee_sign.h
$(TEST_OBJECTS): tee_sign.h keyless_ssl.h keyless_engine.h
$(DEBUG_OBJECTS): tee_sign.h keyless_ssl.h keyless_engine.h