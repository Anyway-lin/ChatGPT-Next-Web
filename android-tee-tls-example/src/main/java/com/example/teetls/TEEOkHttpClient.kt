package com.example.teetls

import android.util.Log
import okhttp3.*
import okhttp3.logging.HttpLoggingInterceptor
import java.util.concurrent.TimeUnit

/**
 * 集成TEE的OkHttp客户端
 * 演示如何在OkHttp中使用基于TEE的自定义TLS引擎
 */
class TEEOkHttpClient private constructor() {
    
    companion object {
        private const val TAG = "TEEOkHttpClient"
        
        /**
         * 创建集成TEE的OkHttp客户端
         */
        fun create(): OkHttpClient {
            return try {
                // 初始化TEE密钥管理器
                val teeKeyManager = TEEKeyManager()
                
                // 创建自定义TLS Socket Factory
                val customSocketFactory = CustomTLSSocketFactory.create(teeKeyManager)
                
                // 创建日志拦截器
                val loggingInterceptor = HttpLoggingInterceptor { message ->
                    Log.d(TAG, "OkHttp: $message")
                }.apply {
                    level = HttpLoggingInterceptor.Level.HEADERS
                }
                
                // 创建自定义拦截器用于添加TEE签名头
                val teeSignatureInterceptor = TEESignatureInterceptor(teeKeyManager)
                
                // 构建OkHttp客户端
                OkHttpClient.Builder()
                    .sslSocketFactory(
                        customSocketFactory,
                        CustomTLSSocketFactory.createTrustManager()
                    )
                    .connectTimeout(30, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .writeTimeout(30, TimeUnit.SECONDS)
                    .addInterceptor(loggingInterceptor)
                    .addInterceptor(teeSignatureInterceptor)
                    .retryOnConnectionFailure(true)
                    .build()
                    .also {
                        Log.d(TAG, "TEE OkHttp客户端创建成功")
                    }
            } catch (e: Exception) {
                Log.e(TAG, "创建TEE OkHttp客户端失败", e)
                throw RuntimeException("创建TEE OkHttp客户端失败", e)
            }
        }
    }
}

/**
 * TEE签名拦截器
 * 为HTTP请求添加基于TEE的数字签名
 */
class TEESignatureInterceptor(
    private val teeKeyManager: TEEKeyManager
) : Interceptor {
    
    companion object {
        private const val TAG = "TEESignatureInterceptor"
        private const val SIGNATURE_HEADER = "X-TEE-Signature"
        private const val TIMESTAMP_HEADER = "X-TEE-Timestamp"
    }
    
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        
        try {
            // 生成时间戳
            val timestamp = System.currentTimeMillis().toString()
            
            // 构建签名数据
            val signatureData = buildSignatureData(originalRequest, timestamp)
            
            // 使用TEE进行签名
            val signature = teeKeyManager.signWithTEE(signatureData.toByteArray())
            val signatureBase64 = android.util.Base64.encodeToString(
                signature, 
                android.util.Base64.NO_WRAP
            )
            
            // 添加签名头到请求
            val signedRequest = originalRequest.newBuilder()
                .addHeader(SIGNATURE_HEADER, signatureBase64)
                .addHeader(TIMESTAMP_HEADER, timestamp)
                .build()
            
            Log.d(TAG, "已为请求添加TEE签名: ${originalRequest.url}")
            
            return chain.proceed(signedRequest)
        } catch (e: Exception) {
            Log.e(TAG, "TEE签名失败", e)
            // 如果签名失败，继续发送原始请求
            return chain.proceed(originalRequest)
        }
    }
    
    /**
     * 构建签名数据
     */
    private fun buildSignatureData(request: Request, timestamp: String): String {
        val method = request.method
        val url = request.url.toString()
        val headers = request.headers.toString()
        
        // 如果有请求体，包含请求体的哈希
        val bodyHash = request.body?.let { body ->
            val buffer = okio.Buffer()
            body.writeTo(buffer)
            val bodyBytes = buffer.readByteArray()
            android.util.Base64.encodeToString(
                java.security.MessageDigest.getInstance("SHA-256").digest(bodyBytes),
                android.util.Base64.NO_WRAP
            )
        } ?: ""
        
        return "$method|$url|$headers|$bodyHash|$timestamp"
    }
}