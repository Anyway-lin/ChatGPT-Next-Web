package com.example.teetls

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*

/**
 * 高级TEE管理器
 * 提供更复杂的TEE操作，包括证书生成、密钥轮换等
 */
class AdvancedTEEManager {
    
    companion object {
        private const val TAG = "AdvancedTEEManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
    
    /**
     * 生成自签名证书
     */
    fun generateSelfSignedCertificate(keyAlias: String): X509Certificate {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            // 获取公钥
            val publicKey = keyStore.getCertificate(keyAlias)?.publicKey
                ?: throw IllegalStateException("无法获取公钥")
            
            // 获取私钥句柄
            val privateKey = keyStore.getKey(keyAlias, null) as PrivateKey
            
            // 证书主题和颁发者
            val subject = X500Name("CN=TEE Client Certificate, O=TEE Example, C=CN")
            val issuer = subject // 自签名
            
            // 证书有效期
            val notBefore = Date()
            val notAfter = Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L) // 1年
            
            // 证书序列号
            val serialNumber = BigInteger.valueOf(System.currentTimeMillis())
            
            // 构建证书
            val certificateBuilder = X509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                SubjectPublicKeyInfo.getInstance(publicKey.encoded)
            )
            
            // 使用TEE中的私钥进行签名
            val contentSigner = JcaContentSignerBuilder("SHA256withECDSA")
                .build(privateKey)
            
            val certificateHolder = certificateBuilder.build(contentSigner)
            val certificate = JcaX509CertificateConverter().getCertificate(certificateHolder)
            
            Log.d(TAG, "自签名证书生成成功")
            return certificate
            
        } catch (e: Exception) {
            Log.e(TAG, "生成自签名证书失败", e)
            throw RuntimeException("生成自签名证书失败", e)
        }
    }
    
    /**
     * 密钥轮换
     */
    fun rotateKey(oldKeyAlias: String, newKeyAlias: String): Boolean {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            // 检查旧密钥是否存在
            if (!keyStore.containsAlias(oldKeyAlias)) {
                Log.w(TAG, "旧密钥不存在: $oldKeyAlias")
                return false
            }
            
            // 生成新密钥
            generateECKey(newKeyAlias)
            
            // 备份操作（如果需要）
            Log.d(TAG, "密钥轮换完成: $oldKeyAlias -> $newKeyAlias")
            
            // 删除旧密钥（可选，根据需求决定）
            // keyStore.deleteEntry(oldKeyAlias)
            
            return true
            
        } catch (e: Exception) {
            Log.e(TAG, "密钥轮换失败", e)
            return false
        }
    }
    
    /**
     * 生成椭圆曲线密钥
     */
    private fun generateECKey(keyAlias: String) {
        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(true)
            .setRandomizedEncryptionRequired(false)
            .build()
        
        keyGenerator.initialize(keyGenParameterSpec)
        keyGenerator.generateKeyPair()
    }
    
    /**
     * 获取密钥信息
     */
    fun getKeyInfo(keyAlias: String): Map<String, Any> {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            if (!keyStore.containsAlias(keyAlias)) {
                return emptyMap()
            }
            
            val certificate = keyStore.getCertificate(keyAlias) as? X509Certificate
            val publicKey = certificate?.publicKey
            
            return mapOf(
                "alias" to keyAlias,
                "algorithm" to (publicKey?.algorithm ?: "unknown"),
                "format" to (publicKey?.format ?: "unknown"),
                "subject" to (certificate?.subjectDN?.name ?: "unknown"),
                "issuer" to (certificate?.issuerDN?.name ?: "unknown"),
                "notBefore" to (certificate?.notBefore ?: Date()),
                "notAfter" to (certificate?.notAfter ?: Date()),
                "serialNumber" to (certificate?.serialNumber ?: BigInteger.ZERO)
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "获取密钥信息失败", e)
            return emptyMap()
        }
    }
    
    /**
     * 验证TEE环境
     */
    fun verifyTEEEnvironment(): TEEEnvironmentInfo {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            // 检查StrongBox支持
            val testKeyAlias = "tee_test_key_${System.currentTimeMillis()}"
            var strongBoxSupported = false
            
            try {
                val keyGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    ANDROID_KEYSTORE
                )
                
                val spec = KeyGenParameterSpec.Builder(
                    testKeyAlias,
                    KeyProperties.PURPOSE_SIGN
                )
                    .setIsStrongBoxBacked(true)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
                
                keyGenerator.initialize(spec)
                keyGenerator.generateKeyPair()
                
                strongBoxSupported = true
                
                // 清理测试密钥
                keyStore.deleteEntry(testKeyAlias)
                
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox不被支持", e)
            }
            
            TEEEnvironmentInfo(
                isAvailable = true,
                strongBoxSupported = strongBoxSupported,
                keystoreProvider = ANDROID_KEYSTORE,
                supportedAlgorithms = listOf("EC", "RSA"),
                supportedDigests = listOf("SHA-256", "SHA-384", "SHA-512")
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "TEE环境验证失败", e)
            TEEEnvironmentInfo(
                isAvailable = false,
                strongBoxSupported = false,
                keystoreProvider = "none",
                supportedAlgorithms = emptyList(),
                supportedDigests = emptyList()
            )
        }
    }
    
    /**
     * 批量签名操作
     */
    fun batchSign(keyAlias: String, dataList: List<ByteArray>): List<ByteArray> {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            val privateKey = keyStore.getKey(keyAlias, null) as PrivateKey
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            
            val results = mutableListOf<ByteArray>()
            
            dataList.forEach { data ->
                signature.update(data)
                results.add(signature.sign())
            }
            
            Log.d(TAG, "批量签名完成，签名数量: ${results.size}")
            return results
            
        } catch (e: Exception) {
            Log.e(TAG, "批量签名失败", e)
            throw RuntimeException("批量签名失败", e)
        }
    }
}

/**
 * TEE环境信息
 */
data class TEEEnvironmentInfo(
    val isAvailable: Boolean,
    val strongBoxSupported: Boolean,
    val keystoreProvider: String,
    val supportedAlgorithms: List<String>,
    val supportedDigests: List<String>
)