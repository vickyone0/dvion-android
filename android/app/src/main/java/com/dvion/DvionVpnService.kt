package com.dvion

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class DvionVpnService : VpnService() {

    companion object {
        private const val TAG          = "DvionVpnService"
        private const val CHANNEL_ID   = "dvion_vpn_channel"
        private const val NOTIF_ID     = 1

        // Intent extras
        const val EXTRA_SERVER      = "server"
        const val EXTRA_AUTH_KEY    = "auth_key"
        const val EXTRA_FULL_TUNNEL = "full_tunnel"
        const val EXTRA_FINGERPRINT = "fingerprint"
        const val ACTION_STOP       = "com.dvion.STOP"

        // Broadcast back to the module
        const val BROADCAST_STATUS  = "com.dvion.VPN_STATUS"
        const val BROADCAST_LOG     = "com.dvion.VPN_LOG"
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }

        val server      = intent?.getStringExtra(EXTRA_SERVER)      ?: return START_NOT_STICKY
        val authKey     = intent.getStringExtra(EXTRA_AUTH_KEY)     ?: return START_NOT_STICKY
        val fullTunnel  = intent.getBooleanExtra(EXTRA_FULL_TUNNEL, false)
        val fingerprint = intent.getStringExtra(EXTRA_FINGERPRINT)

        createNotificationChannel()
        startForeground(NOTIF_ID, buildNotification())
        startVpn(server, authKey, fullTunnel, fingerprint)
        return START_STICKY
    }

    private fun startVpn(server: String, authKey: String, fullTunnel: Boolean, fingerprint: String?) {
        val builder = Builder()
            .setSession("dvion")
            .addAddress("10.0.0.2", 24)
            .addDnsServer("1.1.1.1")

        if (fullTunnel) {
            builder.addRoute("0.0.0.0", 0)
        } else {
            // Split tunnel: only route private/VPN subnets
            builder.addRoute("10.0.0.0", 8)
        }

        tunFd = builder.establish() ?: run {
            broadcastLog("ERROR: Failed to establish TUN interface")
            stopSelf()
            return
        }

        val fd = tunFd!!.fd
        broadcastStatus(true)
        broadcastLog("INFO: TUN established, fd=$fd")

        vpnThread = Thread {
            try {
                // Hand off the TUN fd and connection params to the Rust native library.
                // nativeRunClient blocks until the tunnel exits.
                DvionJni.runClient(fd, server, authKey, fullTunnel, fingerprint ?: "") { line ->
                    broadcastLog(line)
                }
            } catch (e: Exception) {
                Log.e(TAG, "VPN thread error", e)
                broadcastLog("ERROR: ${e.message}")
            } finally {
                broadcastStatus(false)
                stopVpn()
                stopSelf()
            }
        }.also { it.start() }
    }

    private fun stopVpn() {
        vpnThread?.interrupt()
        vpnThread = null
        tunFd?.close()
        tunFd = null
        broadcastStatus(false)
    }

    private fun broadcastStatus(running: Boolean) {
        sendBroadcast(Intent(BROADCAST_STATUS).apply {
            putExtra("running", running)
        })
    }

    private fun broadcastLog(line: String) {
        sendBroadcast(Intent(BROADCAST_LOG).apply {
            putExtra("line", line)
        })
    }

    override fun onRevoke() {
        stopVpn()
        stopSelf()
    }

    private fun createNotificationChannel() {
        val ch = NotificationChannel(CHANNEL_ID, "dvion VPN", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun buildNotification(): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("dvion VPN")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .build()
}
