# TEE Provider 部署指南

本文档详细说明如何在生产环境中部署和配置OpenSSL 3.0.9 TEE Provider。

## 目录

1. [系统要求](#系统要求)
2. [安装步骤](#安装步骤)
3. [配置说明](#配置说明)
4. [集成真实TEE](#集成真实tee)
5. [证书管理](#证书管理)
6. [安全考虑](#安全考虑)
7. [故障排除](#故障排除)
8. [性能优化](#性能优化)

## 系统要求

### 硬件要求
- 支持TEE的ARM处理器（如ARM TrustZone）或Intel SGX
- 最少512MB RAM
- 至少100MB可用存储空间

### 软件要求
- Ubuntu 18.04+ 或其他兼容Linux发行版
- OpenSSL 3.0.9 开发库
- GCC 7.0+ 或Clang 6.0+
- Make构建工具
- TEE开发环境（如OP-TEE、Intel SGX SDK）

### 依赖包安装
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    openssl \
    pkg-config \
    git \
    cmake

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel openssl cmake git
```

## 安装步骤

### 1. 检查OpenSSL版本
```bash
openssl version
# 应该显示: OpenSSL 3.0.9 或更高版本
```

如果版本不匹配，需要编译安装OpenSSL 3.0.9：
```bash
wget https://www.openssl.org/source/openssl-3.0.9.tar.gz
tar -xzf openssl-3.0.9.tar.gz
cd openssl-3.0.9
./Configure linux-x86_64 --prefix=/usr/local/openssl3
make -j$(nproc)
sudo make install
```

### 2. 编译TEE Provider
```bash
cd openssl-tee-provider
make clean
make all OPENSSL_PREFIX=/usr/local/openssl3
```

### 3. 生成生产证书
```bash
# 修改证书生成脚本中的证书信息
vim certs/generate_certs.sh

# 生成证书
make certs
```

### 4. 安装Provider
```bash
sudo make install OPENSSL_PREFIX=/usr/local/openssl3
```

### 5. 验证安装
```bash
make check
```

## 配置说明

### Provider配置文件

创建OpenSSL配置文件 `/etc/ssl/openssl.cnf`：

```ini
# OpenSSL 3.0.9 configuration with TEE Provider

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
tee = tee_sect

[default_sect]
activate = 1

[tee_sect]
module = /usr/local/openssl3/lib/libtee_provider.so
activate = 1
identity = tee_provider
algorithms = RSA:EC:SHA256:AES
```

### 环境变量设置

添加到 `/etc/environment` 或用户的 `~/.bashrc`：

```bash
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export LD_LIBRARY_PATH=/usr/local/openssl3/lib:$LD_LIBRARY_PATH
export PATH=/usr/local/openssl3/bin:$PATH
```

### 应用程序配置

在应用程序中使用TEE Provider：

```c
#include <openssl/provider.h>

int main() {
    // 加载TEE Provider
    OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(NULL, "tee");
    if (!tee_prov) {
        fprintf(stderr, "Failed to load TEE provider\n");
        return 1;
    }
    
    // 使用TEE Provider进行SSL连接
    // ... SSL代码 ...
    
    // 清理
    OSSL_PROVIDER_unload(tee_prov);
    return 0;
}
```

## 集成真实TEE

### OP-TEE集成

1. **安装OP-TEE开发环境**：
```bash
# 获取OP-TEE
git clone https://github.com/OP-TEE/optee_os.git
git clone https://github.com/OP-TEE/optee_client.git

# 编译OP-TEE
cd optee_os
make PLATFORM=vexpress-qemu_virt CFG_TEE_CORE_LOG_LEVEL=4
```

2. **修改TEE接口实现**：

替换 `examples/tee_interface.c` 中的模拟函数：

```c
#include <tee_client_api.h>

// 真实的TEE UUID（需要与TEE应用匹配）
static const TEEC_UUID tee_uuid = {
    0x12345678, 0x1234, 0x1234,
    { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 }
};

int tee_real_sign(const unsigned char *data, size_t data_len,
                  unsigned char *sig, size_t *sig_len,
                  uint32_t key_id, tee_algorithm_t alg) {
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_Result result;
    
    // 初始化TEE上下文
    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        return 0;
    }
    
    // 打开TEE会话
    result = TEEC_OpenSession(&context, &session, &tee_uuid,
                             TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (result != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        return 0;
    }
    
    // 设置操作参数
    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   // 输入数据
        TEEC_MEMREF_TEMP_OUTPUT,  // 输出签名
        TEEC_VALUE_INPUT,         // 密钥ID和算法
        TEEC_NONE);
    
    operation.params[0].tmpref.buffer = (void *)data;
    operation.params[0].tmpref.size = data_len;
    operation.params[1].tmpref.buffer = sig;
    operation.params[1].tmpref.size = *sig_len;
    operation.params[2].value.a = key_id;
    operation.params[2].value.b = alg;
    
    // 调用TEE签名命令
    result = TEEC_InvokeCommand(&session, CMD_SIGN, &operation, NULL);
    
    if (result == TEEC_SUCCESS) {
        *sig_len = operation.params[1].tmpref.size;
    }
    
    // 清理
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    
    return (result == TEEC_SUCCESS) ? 1 : 0;
}
```

### Intel SGX集成

1. **安装SGX SDK**：
```bash
wget https://download.01.org/intel-sgx/sgx-linux/2.17/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.17.101.1.bin
chmod +x sgx_linux_x64_sdk_2.17.101.1.bin
sudo ./sgx_linux_x64_sdk_2.17.101.1.bin
```

2. **创建SGX Enclave**：

参考SGX文档创建包含密钥操作的Enclave。

## 证书管理

### 生产证书部署

1. **替换测试证书**：
```bash
# 备份测试证书
mv certs certs_test

# 部署生产证书
mkdir certs
cp /secure/location/root_cert.pem certs/
cp /secure/location/device_cert.pem certs/
# 注意：不要复制私钥文件到主机
```

2. **证书链验证**：
```bash
# 验证证书链
openssl verify -CAfile certs/root_cert.pem certs/device_cert.pem
```

3. **证书更新流程**：
```bash
#!/bin/bash
# 证书更新脚本

NEW_CERT_DIR="/tmp/new_certs"
BACKUP_DIR="/backup/certs_$(date +%Y%m%d)"

# 备份当前证书
mkdir -p "$BACKUP_DIR"
cp -r certs/* "$BACKUP_DIR/"

# 验证新证书
if openssl verify -CAfile "$NEW_CERT_DIR/root_cert.pem" "$NEW_CERT_DIR/device_cert.pem"; then
    # 更新证书
    cp "$NEW_CERT_DIR"/* certs/
    echo "Certificate update successful"
    
    # 重启相关服务
    systemctl restart your-tee-service
else
    echo "Certificate verification failed"
    exit 1
fi
```

## 安全考虑

### 权限设置
```bash
# 设置严格的文件权限
sudo chmod 600 certs/*.pem
sudo chown root:ssl-cert certs/*.pem

# 限制Provider库访问
sudo chmod 755 /usr/local/openssl3/lib/libtee_provider.so
sudo chown root:root /usr/local/openssl3/lib/libtee_provider.so
```

### SELinux配置
```bash
# 创建SELinux策略（如果使用SELinux）
sudo setsebool -P allow_execstack 1
sudo semanage fcontext -a -t lib_t "/usr/local/openssl3/lib/libtee_provider.so"
sudo restorecon -v /usr/local/openssl3/lib/libtee_provider.so
```

### 日志和审计
```bash
# 配置日志记录
echo "local0.*    /var/log/tee-provider.log" >> /etc/rsyslog.conf
systemctl restart rsyslog

# 启用审计
auditctl -w /usr/local/openssl3/lib/libtee_provider.so -p rwxa -k tee_provider
```

## 故障排除

### 常见问题

1. **Provider加载失败**：
```bash
# 检查库依赖
ldd /usr/local/openssl3/lib/libtee_provider.so

# 检查OpenSSL版本
openssl version

# 查看详细错误
export OPENSSL_TRACE=provider
./your_application
```

2. **证书验证失败**：
```bash
# 检查证书有效性
openssl x509 -in certs/device_cert.pem -text -noout

# 验证证书链
openssl verify -verbose -CAfile certs/root_cert.pem certs/device_cert.pem
```

3. **TEE连接问题**：
```bash
# 检查TEE服务状态
systemctl status optee
# 或
systemctl status aesmd  # Intel SGX

# 检查设备权限
ls -la /dev/tee*
```

### 调试技巧

1. **启用详细日志**：
```c
// 在代码中添加调试输出
#ifdef DEBUG
#define DBG_PRINT(fmt, ...) printf("[TEE DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif
```

2. **使用GDB调试**：
```bash
gdb --args ./your_application
(gdb) set environment OPENSSL_TRACE=provider
(gdb) run
```

3. **内存检查**：
```bash
valgrind --tool=memcheck --leak-check=full ./your_application
```

## 性能优化

### 缓存优化
```c
// 在Provider中实现会话缓存
typedef struct {
    uint32_t key_id;
    void *tee_session;
    time_t last_used;
} tee_session_cache_t;

static tee_session_cache_t session_cache[MAX_SESSIONS];
```

### 连接池
```c
// TEE连接池管理
typedef struct {
    TEEC_Context *contexts;
    TEEC_Session *sessions;
    int active_count;
    int max_count;
} tee_connection_pool_t;
```

### 监控指标
```bash
# 创建性能监控脚本
#!/bin/bash
echo "TEE Provider Performance Metrics:"
echo "================================"
echo "Active sessions: $(netstat -an | grep :8443 | wc -l)"
echo "Memory usage: $(ps aux | grep tee | awk '{sum+=$6} END {print sum/1024 " MB"}')"
echo "CPU usage: $(top -bn1 | grep tee | awk '{print $9"%"}')"
```

## 维护建议

1. **定期更新**：
   - 每月检查OpenSSL安全更新
   - 每季度更新TEE固件
   - 年度证书更新

2. **备份策略**：
   - 每日备份配置文件
   - 每周备份证书（公钥部分）
   - 每月全系统备份

3. **监控检查**：
   - 实时监控Provider状态
   - 定期检查证书有效期
   - 监控TEE资源使用情况

4. **安全审计**：
   - 月度安全扫描
   - 季度渗透测试
   - 年度安全评估

## 技术支持

如遇到问题，请提供以下信息：
- 系统版本和架构
- OpenSSL版本
- TEE环境详细信息
- 错误日志和调试输出
- 复现步骤

联系方式：
- GitHub Issues: [项目地址]
- 邮箱: [支持邮箱]
- 文档: [在线文档地址]