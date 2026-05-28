package com.dvion

/**
 * JNI bridge to the compiled Rust dvion client library (libdvion_jni.so).
 * The native library must be built with cargo-ndk and placed in jniLibs/.
 */
object DvionJni {

    init {
        System.loadLibrary("dvion_jni")
    }

    /**
     * Runs the dvion client. Blocks until the tunnel exits or the thread is interrupted.
     * [logCallback] is called on the calling thread for each log line.
     */
    external fun runClient(
        tunFd:       Int,
        server:      String,
        authKey:     String,
        fullTunnel:  Boolean,
        fingerprint: String,
        logCallback: LogCallback,
    )

    /** Generates a new auth key (same as `dvion keygen`). */
    external fun generateKey(): String

    fun interface LogCallback {
        fun onLine(line: String)
    }
}
