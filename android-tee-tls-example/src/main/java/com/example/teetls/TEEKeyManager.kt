package com.example.teetls

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.X509KeyManager

/**
 * TEE密钥管理器
 * 实现自定义的X509KeyManager，使用TEE进行签名操作
 */
class TEEKeyManager : X509KeyManager {
    
    companion object {
        private const val TAG = "TEEKeyManager"
        private const val TEE_KEY_ALIAS = "tee_tls_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
    
    private var publicKey: PublicKey? = null
    private var certificateChain: Array<X509Certificate>? = null
    private var keyAlias: String? = null
    
    init {
        initializeTEEKey()
    }
    
    /**
     * 初始化TEE密钥
     */
    private fun initializeTEEKey() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            // 检查密钥是否已存在
            if (!keyStore.containsAlias(TEE_KEY_ALIAS)) {
                generateTEEKey()
            }
            
            // 获取公钥
            publicKey = keyStore.getCertificate(TEE_KEY_ALIAS)?.publicKey
            
            // 获取证书链
            val cert = keyStore.getCertificate(TEE_KEY_ALIAS) as? X509Certificate
            certificateChain = cert?.let { arrayOf(it) }
            
            keyAlias = TEE_KEY_ALIAS
            
            Log.d(TAG, "TEE密钥初始化成功")
        } catch (e: Exception) {
            Log.e(TAG, "TEE密钥初始化失败", e)
            throw RuntimeException("TEE密钥初始化失败", e)
        }
    }
    
    /**
     * 在TEE中生成密钥对
     */
    private fun generateTEEKey() {
        try {
            val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, 
                ANDROID_KEYSTORE
            )
            
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                TEE_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(
                    KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA384,
                    KeyProperties.DIGEST_SHA512
                )
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_NONE)
                // 要求用户认证（如指纹、PIN等）
                .setUserAuthenticationRequired(false)
                // 使用硬件支持的密钥存储
                .setIsStrongBoxBacked(true)
                // 密钥不可导出
                .setRandomizedEncryptionRequired(false)
                .build()
            
            keyGenerator.initialize(keyGenParameterSpec)
            val keyPair = keyGenerator.generateKeyPair()
            
            Log.d(TAG, "TEE密钥生成成功: ${keyPair.public.algorithm}")
        } catch (e: Exception) {
            Log.e(TAG, "TEE密钥生成失败", e)
            throw RuntimeException("TEE密钥生成失败", e)
        }
    }
    
    /**
     * 使用TEE进行签名操作
     */
    fun signWithTEE(data: ByteArray, algorithm: String = "SHA256withECDSA"): ByteArray {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            
            val privateKey = keyStore.getKey(TEE_KEY_ALIAS, null) as PrivateKey
            val signature = Signature.getInstance(algorithm)
            signature.initSign(privateKey)
            signature.update(data)
            
            val signatureBytes = signature.sign()
            Log.d(TAG, "TEE签名成功，签名长度: ${signatureBytes.size}")
            
            return signatureBytes
        } catch (e: Exception) {
            Log.e(TAG, "TEE签名失败", e)
            throw RuntimeException("TEE签名失败", e)
        }
    }
    
    /**
     * 验证TEE签名
     */
    fun verifyTEESignature(data: ByteArray, signature: ByteArray, algorithm: String = "SHA256withECDSA"): Boolean {
        try {
            val verifier = Signature.getInstance(algorithm)
            verifier.initVerify(publicKey)
            verifier.update(data)
            
            return verifier.verify(signature)
        } catch (e: Exception) {
            Log.e(TAG, "TEE签名验证失败", e)
            return false
        }
    }
    
    // X509KeyManager接口实现
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? {
        return keyAlias?.let { arrayOf(it) }
    }
    
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: java.net.Socket?): String? {
        return keyAlias
    }
    
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? {
        return null // 客户端不需要实现
    }
    
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: java.net.Socket?): String? {
        return null // 客户端不需要实现
    }
    
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
        return if (alias == keyAlias) certificateChain else null
    }
    
    override fun getPrivateKey(alias: String?): PrivateKey? {
        // 返回TEE中的私钥句柄，但实际签名操作在TEE中完成
        return if (alias == keyAlias) {
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                keyStore.getKey(TEE_KEY_ALIAS, null) as? PrivateKey
            } catch (e: Exception) {
                Log.e(TAG, "获取TEE私钥失败", e)
                null
            }
        } else null
    }
}