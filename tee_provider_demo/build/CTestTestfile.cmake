# CMake generated Testfile for 
# Source directory: /workspace/tee_provider_demo
# Build directory: /workspace/tee_provider_demo/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(build_test "/usr/bin/cmake" "--build" "/workspace/tee_provider_demo/build" "--target" "all")
set_tests_properties(build_test PROPERTIES  _BACKTRACE_TRIPLES "/workspace/tee_provider_demo/CMakeLists.txt;86;add_test;/workspace/tee_provider_demo/CMakeLists.txt;0;")
add_test(cert_generation_test "/workspace/tee_provider_demo/generate_certs.sh")
set_tests_properties(cert_generation_test PROPERTIES  WORKING_DIRECTORY "/workspace/tee_provider_demo/build" _BACKTRACE_TRIPLES "/workspace/tee_provider_demo/CMakeLists.txt;91;add_test;/workspace/tee_provider_demo/CMakeLists.txt;0;")
add_test(library_test "ldd" "/workspace/tee_provider_demo/build/tls_client")
set_tests_properties(library_test PROPERTIES  _BACKTRACE_TRIPLES "/workspace/tee_provider_demo/CMakeLists.txt;97;add_test;/workspace/tee_provider_demo/CMakeLists.txt;0;")
