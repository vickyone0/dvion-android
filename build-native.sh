#!/usr/bin/env bash
# Build the Rust JNI library for Android and copy .so files into jniLibs/.
# Prerequisites: cargo-ndk (`cargo install cargo-ndk`) + Android NDK in $ANDROID_NDK_HOME.
set -euo pipefail

BRIDGE_DIR="$(cd "$(dirname "$0")/rust-bridge" && pwd)"
OUT_DIR="$(cd "$(dirname "$0")/android/app/src/main/jniLibs" && pwd)"

TARGETS=(
  "aarch64-linux-android:arm64-v8a"
  "x86_64-linux-android:x86_64"
)

echo "==> Building dvion JNI library..."
cd "$BRIDGE_DIR"

for entry in "${TARGETS[@]}"; do
  TARGET="${entry%%:*}"
  ABI="${entry##*:}"

  echo "  -> $TARGET ($ABI)"
  cargo ndk --target "$TARGET" --platform 26 -- build --release

  mkdir -p "$OUT_DIR/$ABI"
  cp "target/$TARGET/release/libdvion_jni.so" "$OUT_DIR/$ABI/libdvion_jni.so"
  echo "     copied to jniLibs/$ABI/"
done

echo "==> Done. Run 'cd android && ./gradlew assembleRelease' to build the APK."
