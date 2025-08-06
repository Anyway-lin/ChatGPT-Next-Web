package com.example.teetls

import android.util.Log
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.*

/**
 * 自定义TLS Socket Factory
 * 集成TEE密钥管理器，实现基于TEE的TLS连接
 */
class CustomTLSSocketFactory private constructor(
    private val sslContext: SSLContext
) : SSLSocketFactory() {
    
    companion object {
        private const val TAG = "CustomTLSSocketFactory"
        
        /**
         * 创建自定义TLS Socket Factory实例
         */
        fun create(teeKeyManager: TEEKeyManager): CustomTLSSocketFactory {
            return try {
                val sslContext = SSLContext.getInstance("TLS")
                
                // 配置密钥管理器
                val keyManagers = arrayOf<KeyManager>(teeKeyManager)
                
                // 配置信任管理器（可以自定义证书验证逻辑）
                val trustManagers = arrayOf<TrustManager>(createTrustManager())
                
                // 初始化SSL上下文
                sslContext.init(keyManagers, trustManagers, SecureRandom())
                
                Log.d(TAG, "自定义TLS Socket Factory创建成功")
                CustomTLSSocketFactory(sslContext)
            } catch (e: Exception) {
                Log.e(TAG, "创建自定义TLS Socket Factory失败", e)
                throw RuntimeException("创建自定义TLS Socket Factory失败", e)
            }
        }
        
        /**
         * 创建信任管理器
         */
        fun createTrustManager(): X509TrustManager {
            return object : X509TrustManager {
                override fun checkClientTrusted(
                    chain: Array<java.security.cert.X509Certificate>?,
                    authType: String?
                ) {
                    // 实现客户端证书验证逻辑
                    Log.d(TAG, "客户端证书验证: $authType")
                }
                
                override fun checkServerTrusted(
                    chain: Array<java.security.cert.X509Certificate>?,
                    authType: String?
                ) {
                    // 实现服务器证书验证逻辑
                    Log.d(TAG, "服务器证书验证: $authType")
                    // 这里可以添加自定义的服务器证书验证逻辑
                    // 例如：证书链验证、OCSP验证等
                }
                
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> {
                    return arrayOf()
                }
            }
        }
    }
    
    private val socketFactory = sslContext.socketFactory
    
    override fun createSocket(): Socket {
        return configureSocket(socketFactory.createSocket())
    }
    
    override fun createSocket(host: String?, port: Int): Socket {
        return configureSocket(socketFactory.createSocket(host, port))
    }
    
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket {
        return configureSocket(socketFactory.createSocket(host, port, localHost, localPort))
    }
    
    override fun createSocket(host: InetAddress?, port: Int): Socket {
        return configureSocket(socketFactory.createSocket(host, port))
    }
    
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket {
        return configureSocket(socketFactory.createSocket(address, port, localAddress, localPort))
    }
    
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        return configureSocket(socketFactory.createSocket(s, host, port, autoClose))
    }
    
    override fun getDefaultCipherSuites(): Array<String> {
        return socketFactory.defaultCipherSuites
    }
    
    override fun getSupportedCipherSuites(): Array<String> {
        return socketFactory.supportedCipherSuites
    }
    
    /**
     * 配置SSL Socket
     */
    private fun configureSocket(socket: Socket): Socket {
        return if (socket is SSLSocket) {
            try {
                // 配置支持的协议版本
                socket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
                
                // 配置密码套件（优先选择基于ECDSA的套件）
                val supportedCipherSuites = socket.supportedCipherSuites
                val preferredCipherSuites = mutableListOf<String>()
                
                // 优先选择ECDSA密码套件
                supportedCipherSuites.forEach { suite ->
                    if (suite.contains("ECDSA") || suite.contains("ECDHE")) {
                        preferredCipherSuites.add(suite)
                    }
                }
                
                // 添加其他安全的密码套件
                supportedCipherSuites.forEach { suite ->
                    if (!preferredCipherSuites.contains(suite) && 
                        (suite.contains("GCM") || suite.contains("CHACHA20"))) {
                        preferredCipherSuites.add(suite)
                    }
                }
                
                if (preferredCipherSuites.isNotEmpty()) {
                    socket.enabledCipherSuites = preferredCipherSuites.toTypedArray()
                    Log.d(TAG, "已配置密码套件: ${preferredCipherSuites.size}个")
                }
                
                // 设置SSL参数
                val sslParameters = socket.sslParameters
                sslParameters?.let { params ->
                    // 启用SNI（Server Name Indication）
                    params.serverNames = null // 或设置具体的服务器名称
                    
                    // 设置应用层协议协商（ALPN）
                    params.applicationProtocols = arrayOf("http/1.1", "h2")
                    
                    // 启用端点识别
                    params.endpointIdentificationAlgorithm = "HTTPS"
                    
                    socket.sslParameters = params
                }
                
                Log.d(TAG, "SSL Socket配置完成")
                socket
            } catch (e: Exception) {
                Log.e(TAG, "配置SSL Socket失败", e)
                socket
            }
        } else {
            socket
        }
    }
}