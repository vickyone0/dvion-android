package com.dvion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule

class VpnModule(private val ctx: ReactApplicationContext) :
    ReactContextBaseJavaModule(ctx) {

    companion object {
        private const val VPN_PERMISSION_REQUEST = 1001
    }

    override fun getName() = "DvionVpnModule"

    // ── Receivers ──────────────────────────────────────────────────────────
    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val running = intent.getBooleanExtra("running", false)
            val map = Arguments.createMap().apply {
                putBoolean("running", running)
                putString("mode", if (running) "client" else null)
                putInt("uptime_secs", 0)
            }
            emit("vpn-status", map)
        }
    }

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            emit("vpn-log", intent.getStringExtra("line") ?: "")
        }
    }

    init {
        ctx.registerReceiver(statusReceiver, IntentFilter(DvionVpnService.BROADCAST_STATUS),
            Context.RECEIVER_NOT_EXPORTED)
        ctx.registerReceiver(logReceiver, IntentFilter(DvionVpnService.BROADCAST_LOG),
            Context.RECEIVER_NOT_EXPORTED)
    }

    // ── JS-callable methods ────────────────────────────────────────────────

    @ReactMethod
    fun getStatus(promise: Promise) {
        val map = Arguments.createMap().apply {
            putBoolean("running", false)
            putNull("mode")
            putInt("uptime_secs", 0)
        }
        promise.resolve(map)
    }

    @ReactMethod
    fun connect(
        server:      String,
        authKey:     String,
        fullTunnel:  Boolean,
        fingerprint: String?,
        promise:     Promise,
    ) {
        val activity = currentActivity ?: run { promise.reject("NO_ACTIVITY", "No activity"); return }

        // Check or request VPN permission
        val vpnIntent = VpnService.prepare(ctx)
        if (vpnIntent != null) {
            // The user must approve the VPN connection — start the system dialog.
            // After approval, the activity should call connect again.
            activity.startActivityForResult(vpnIntent, VPN_PERMISSION_REQUEST)
            promise.reject("PERMISSION_REQUIRED", "VPN permission dialog shown")
            return
        }

        val svcIntent = Intent(ctx, DvionVpnService::class.java).apply {
            putExtra(DvionVpnService.EXTRA_SERVER,      server)
            putExtra(DvionVpnService.EXTRA_AUTH_KEY,    authKey)
            putExtra(DvionVpnService.EXTRA_FULL_TUNNEL, fullTunnel)
            putExtra(DvionVpnService.EXTRA_FINGERPRINT, fingerprint)
        }
        ctx.startForegroundService(svcIntent)
        promise.resolve(null)
    }

    @ReactMethod
    fun disconnect(promise: Promise) {
        val stopIntent = Intent(ctx, DvionVpnService::class.java).apply {
            action = DvionVpnService.ACTION_STOP
        }
        ctx.startService(stopIntent)
        promise.resolve(null)
    }

    @ReactMethod
    fun generateKey(promise: Promise) {
        try {
            promise.resolve(DvionJni.generateKey())
        } catch (e: Exception) {
            promise.reject("KEYGEN_ERROR", e.message)
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun emit(event: String, payload: Any?) {
        ctx.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(event, payload)
    }

    // Required for RN event emitter compatibility
    @ReactMethod fun addListener(@Suppress("UNUSED_PARAMETER") event: String) {}
    @ReactMethod fun removeListeners(@Suppress("UNUSED_PARAMETER") count: Int) {}

    override fun invalidate() {
        super.invalidate()
        runCatching { ctx.unregisterReceiver(statusReceiver) }
        runCatching { ctx.unregisterReceiver(logReceiver) }
    }
}
