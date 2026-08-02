# IneQr public surface — keep classes the JNI bridge references by name.
-keep class mx.ine.qr.IneResult { *; }
-keep class mx.ine.qr.IneQr$Error { *; }
-keep class mx.ine.qr.IneQr$Error$* { *; }
-keepclasseswithmembernames class mx.ine.qr.internal.NativeBridge {
    native <methods>;
}
