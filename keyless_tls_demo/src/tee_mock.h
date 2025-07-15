#ifndef TEE_MOCK_H
#define TEE_MOCK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// TeeKeyPurpose枚举定义
enum TeeKeyPurpose {
    KM_PURPOSE_ENCRYPT = 0,         // 使用私钥加密(未使用)
    KM_PURPOSE_DECRYPT = 1,         // 使用私钥解密
    KM_PURPOSE_SIGN = 2,            // 使用私钥签名
    KM_PURPOSE_VERIFY = 3,          // (未使用)
    KM_PURPOSE_DERIVE_KEY = 4,      // (未使用)
    KM_PURPOSE_WRAP = 0xFFFF001,    // (未使用)
    KM_PURPOSE_UNWRAP = 0xFFFF002   // (未使用)
};

// padType枚举定义
enum TeePadType {
    KM_PAD_NONE = 1,                    // 无填充
    KM_PAD_RSA_OAEP = 2,               // 使用OAEP填充
    KM_PAD_RSA_PSS = 3,                // 使用PSS填充(未使用)
    KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4,  // 使用PKCS#1 v1.5标准的加密填充
    KM_PAD_RSA_PKCS1_1_5_SIGN = 5,     // 使用PKCS#1 v1.5标准的签名填充(未使用)
    KM_PAD_PKCS7 = 64                   // 使用PKCS#7填充(未使用)
};

// TeeBlob结构体定义
struct TeeBlob {
    uint8_t *data;         // 数据缓存区
    size_t dataLength;     // 缓存区长度
};

/**
 * TEE密钥操作函数
 * @param purpose 操作类型
 * @param padType 填充模式
 * @param inData 输入数据
 * @param outData 输出数据
 * @return 0成功，其他值表示错误
 */
int32_t TeeKeylessOperation(enum TeeKeyPurpose purpose, uint32_t padType, 
                           struct TeeBlob *inData, struct TeeBlob *outData);

/**
 * 初始化TEE模拟环境
 * @param device_key_path 设备私钥文件路径
 * @return 0成功，其他值表示错误
 */
int32_t TeeInit(const char *device_key_path);

/**
 * 清理TEE模拟环境
 */
void TeeCleanup(void);

/**
 * 获取设备证书（用于证书链构建）
 * @param cert_data 输出证书数据
 * @return 0成功，其他值表示错误
 */
int32_t TeeGetDeviceCertificate(struct TeeBlob *cert_data);

#ifdef __cplusplus
}
#endif

#endif // TEE_MOCK_H