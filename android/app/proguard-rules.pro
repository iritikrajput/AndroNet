# Flutter / Dart VM
-keep class io.flutter.** { *; }
-keep class io.flutter.embedding.** { *; }
-keep class io.flutter.plugin.** { *; }
-dontwarn io.flutter.**

# AndroNet JNI — native methods called from C/C++ must not be renamed
-keep class com.example.packet_analyzer.ZdtunVpn { *; }
-keep class com.example.packet_analyzer.LibpcapBridge { *; }
-keep class com.example.packet_analyzer.PcapWriter { *; }
-keep class com.example.packet_analyzer.ZdtunVpnService {
    void sendPacketToVpn(byte[]);
    boolean protectSocket(int);
}
-keep class com.example.packet_analyzer.NetHunterService {
    void onPacketCaptured(java.util.Map);
    void onStatusUpdate(java.lang.String);
}

# Services — must survive shrinking so the OS can start them
-keep class com.example.packet_analyzer.ZdtunVpnService { *; }
-keep class com.example.packet_analyzer.NetHunterService { *; }
-keep class com.example.packet_analyzer.MainActivity { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-dontwarn kotlinx.coroutines.**

# Biometric
-keep class androidx.biometric.** { *; }
-dontwarn androidx.biometric.**

# Multidex
-keep class androidx.multidex.** { *; }

# Retain source file names and line numbers for crash stack traces
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
