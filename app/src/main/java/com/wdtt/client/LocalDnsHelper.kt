package com.wdtt.client

import android.content.Context
import android.net.ConnectivityManager
import java.net.Inet4Address

/**
 * Локальный DNS текущей сети (оператора/Wi-Fi), выданный через DHCP/APN.
 * Используется как аварийный запасной вариант, если ни один из настроенных
 * DNS (Яндекс/Cloudflare/Google/DoH/свой) недоступен.
 */
object LocalDnsHelper {
    fun systemDnsServers(context: Context): List<String> {
        return try {
            val cm = context.applicationContext
                .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return emptyList()
            val network = cm.activeNetwork ?: return emptyList()
            val linkProperties = cm.getLinkProperties(network) ?: return emptyList()
            linkProperties.dnsServers
                // Формат "custom:IP,IP" (Kotlin-проверка и Go-клиент) поддерживает только IPv4.
                .filterIsInstance<Inet4Address>()
                .mapNotNull { it.hostAddress }
                .filter { it.isNotBlank() && it != "0.0.0.0" }
                .distinct()
        } catch (_: Exception) {
            emptyList()
        }
    }
}
