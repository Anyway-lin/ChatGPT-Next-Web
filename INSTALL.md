# TEE Provider 快速安装指南

## 环境准备

### 1. 确认OpenSSL版本

```bash
openssl version
# 输出应为: OpenSSL 3.0.9 或更高版本
```

如果版本过低，在Ubuntu上可以这样安装：

```bash
# Ubuntu 22.04+
sudo apt update
sudo apt install openssl libssl-dev

# 或者编译安装最新版本
# wget https://www.openssl.org/source/openssl-3.0.9.tar.gz
# tar -xzf openssl-3.0.9.tar.gz
# cd openssl-3.0.9
# ./config --prefix=/usr/local/openssl
# make && sudo make install
```

### 2. 安装编译工具

```bash
sudo apt update
sudo apt install build-essential gcc make
```

## 快速安装

### 方法一：一键安装（推荐）

```bash
# 克隆项目
git clone <your-repo-url>
cd tee-provider

# 一键编译和测试
make && make setup-test && make test
```

### 方法二：分步安装

```bash
# 1. 编译Provider
make

# 2. 生成测试证书
make setup-test

# 3. 运行测试
make test

# 4. 可选：安装到系统目录
sudo make install
```

## 验证安装

### 1. 检查Provider是否正确加载

```bash
export OPENSSL_CONF=$(pwd)/tee_openssl.cnf
openssl list -providers
```

应该看到类似输出：
```
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.9
    status: active
  tee
    name: TEE Provider
    version: 1.0.0
    status: active
```

### 2. 测试TEE密钥签名

```bash
echo "test" > test.txt
openssl pkeyutl -provider tee -provider default \
    -inkey "tee:device_rsa" \
    -sign -in test.txt -out signature.bin

echo "✓ 签名成功"
```

### 3. 测试C客户端

```bash
gcc -o test_client test_client.c -lssl -lcrypto
./test_client
```

## 常见问题

### Q: Provider加载失败

**现象**: `openssl list -providers` 没有显示tee provider

**解决**:
```bash
# 检查共享库路径
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# 检查依赖
ldd tee_provider.so

# 检查配置文件
cat tee_openssl.cnf
```

### Q: 找不到头文件

**现象**: 编译时报错 `openssl/core.h: No such file or directory`

**解决**:
```bash
# 安装开发包
sudo apt install libssl-dev

# 或指定OpenSSL路径
make OPENSSL_PREFIX=/usr/local/openssl
```

### Q: 权限错误

**现象**: 无法创建或读取文件

**解决**:
```bash
# 检查脚本权限
chmod +x setup_test_certs.sh test_tee_provider.sh

# 检查证书文件权限
ls -la *.pem
```

## 生产环境部署

### 1. 编译release版本

```bash
make clean
make CFLAGS="-O2 -DNDEBUG"
```

### 2. 安装到系统目录

```bash
sudo make install PROVIDER_DIR=/usr/lib/x86_64-linux-gnu/ossl-modules
```

### 3. 配置系统级OpenSSL

```bash
sudo cp tee_openssl.cnf /etc/ssl/openssl.cnf.d/tee.cnf
```

### 4. 集成到应用

在应用程序中设置：
```c
setenv("OPENSSL_CONF", "/etc/ssl/openssl.cnf.d/tee.cnf", 1);
OSSL_PROVIDER_load(NULL, "tee");
OSSL_PROVIDER_load(NULL, "default");
```

## 下一步

- 阅读 [README.md](README.md) 了解详细使用方法
- 查看 [test_client.c](test_client.c) 学习编程接口
- 根据您的TEE环境修改 `tee_provider.c` 中的接口实现

---

🎉 安装完成！现在您可以使用TEE Provider在没有私钥文件的情况下进行OpenSSL操作了。