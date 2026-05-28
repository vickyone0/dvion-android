use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, JNI_TRUE};
use jni::JNIEnv;
use std::os::unix::io::FromRawFd;

// ── JNI: runClient ──────────────────────────────────────────────────────────
//
// Called from Kotlin: DvionJni.runClient(tunFd, server, authKey, fullTunnel, fingerprint, cb)
// Blocks until the tunnel exits.

#[no_mangle]
pub extern "system" fn Java_com_dvion_DvionJni_runClient(
    mut env:       JNIEnv,
    _class:        JClass,
    tun_fd:        jint,
    j_server:      JString,
    j_auth_key:    JString,
    full_tunnel:   jboolean,
    j_fingerprint: JString,
    log_callback:  JObject,
) {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default().with_tag("dvion_jni"),
    );

    dvion_vpn::transport::install_crypto_provider();

    let server      = jstr(&mut env, j_server);
    let auth_key    = jstr(&mut env, j_auth_key);
    let fingerprint = jstr(&mut env, j_fingerprint);
    let full_tunnel = full_tunnel == JNI_TRUE;

    // dup the fd so that when File takes ownership and closes on drop,
    // Android's ParcelFileDescriptor (which holds the original) stays valid.
    let dup_fd = unsafe { libc::dup(tun_fd) };
    let tun_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };

    let jvm = env.get_java_vm().expect("get jvm");
    let cb  = env.new_global_ref(log_callback).expect("global ref");

    let log_fn = move |line: String| {
        if let Ok(mut je) = jvm.attach_current_thread() {
            if let Ok(jline) = je.new_string(&line) {
                let _ = je.call_method(
                    cb.as_obj(),
                    "onLine",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&jline)],
                );
            }
        }
    };

    let fp = if fingerprint.is_empty() {
        None
    } else {
        dvion_vpn::transport::parse_fingerprint(&fingerprint).ok()
    };

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(
        dvion_vpn::transport::run_client_with_tun(tun_file, &server, &auth_key, full_tunnel, fp, log_fn)
    ) {
        eprintln!("dvion tunnel error: {e}");
    }
}

// ── JNI: generateKey ────────────────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_dvion_DvionJni_generateKey<'local>(
    env: JNIEnv<'local>,
    _class:  JClass,
) -> jni::objects::JString<'local> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let body: String = (0..32)
        .map(|_| {
            let i = rng.gen_range(0..36usize);
            if i < 10 { (b'0' + i as u8) as char } else { (b'a' + (i - 10) as u8) as char }
        })
        .collect();
    let key = format!("dvion-{body}");
    env.new_string(key).expect("new_string")
}

// ── Helper ───────────────────────────────────────────────────────────────────

fn jstr(env: &mut JNIEnv, s: JString) -> String {
    env.get_string(&s).map(|cs| cs.into()).unwrap_or_default()
}

extern crate libc;
