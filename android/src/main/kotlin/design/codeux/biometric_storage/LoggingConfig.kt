package design.codeux.biometric_storage


import android.util.Log
import io.github.oshai.kotlinlogging.KotlinLogging
import io.github.oshai.kotlinlogging.Level

// Проста функція для ручного логування у Logcat
fun setupAndroidLogging() {
    System.setProperty("kotlin.logging.level", "TRACE")
}

// Розширення для швидкого виводу у Logcat
fun logToAndroid(level: Level, message: String, throwable: Throwable? = null) {
    val tag = "BiometricStorage"
    when (level) {
        Level.ERROR -> Log.e(tag, message, throwable)
        Level.WARN -> Log.w(tag, message, throwable)
        Level.INFO -> Log.i(tag, message, throwable)
        Level.DEBUG -> Log.d(tag, message, throwable)
        Level.TRACE -> Log.v(tag, message, throwable)
        else -> Log.v(tag, message, throwable)
    }
}