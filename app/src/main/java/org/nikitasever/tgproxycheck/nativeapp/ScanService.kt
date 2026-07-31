package org.nikitasever.tgproxycheck.nativeapp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val SCAN_SERVICE_TAG = "TgProxyScanService"
private const val SCAN_NOTIFICATION_CHANNEL_ID = "scan_progress"
private const val SCAN_NOTIFICATION_ID = 1001

// How often (ms) the ongoing notification is allowed to be re-posted while a
// scan is running. onProgress fires once per candidate (up to ~450 times a
// run), and NotificationManagerCompat.notify() on every single one of those
// would hammer the system notification service for no visible benefit -
// nobody can perceive a status-bar text change faster than this anyway.
private const val NOTIFICATION_THROTTLE_MS = 400L

// Telegram-blue accent (matches TgAccent in MainActivity.kt's Compose theme)
// used for the colorized progress notification - see the setColorized(true)
// note on buildProgressNotification() for why a colorized notification
// needs an explicit color at all.
private val TG_ACCENT_COLOR = android.graphics.Color.parseColor("#2AABEE")

const val ACTION_START_SCAN = "org.nikitasever.tgproxycheck.nativeapp.action.START_SCAN"

// Everything the UI needs to render the scan header/results, mirrored between
// the (possibly backgrounded/destroyed-and-recreated) Activity and the
// foreground ScanService that's the one thing actually still running the scan.
data class ScanUiState(
    val isScanning: Boolean = false,
    val checked: Int = 0,
    val total: Int = 0,
    val statusLine: String? = null,
    val aliveResults: List<AliveHit> = emptyList(),
    val lastScanInfo: String? = null,
    val totalCheckedLast: Int = 0,
    val everScanned: Boolean = false,
)

// Process-wide bridge between the Activity's Compose UI and ScanService. A
// plain singleton object rather than a bound-service connection: this app
// runs one scan at a time from one Activity, so the extra bind/unbind
// lifecycle machinery a proper Service connection needs would buy nothing
// here, and a singleton StateFlow is trivially readable from both sides
// regardless of which of the two is currently alive.
object ScanBridge {
    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    fun update(transform: (ScanUiState) -> ScanUiState) {
        _state.value = transform(_state.value)
    }

    // Seeds the bridge with the persisted last-scan snapshot on a cold start.
    // Guarded so it only ever applies to a truly untouched bridge - it must
    // never clobber live/finished scan state if the Activity is merely being
    // recreated (e.g. rotation) while the bridge already holds real state.
    fun seedIfEmpty(snapshot: ScanUiState) {
        if (_state.value == ScanUiState()) {
            _state.value = snapshot
        }
    }
}

// Foreground Service driving the mass scan so it (and its status-bar/
// notification-shade progress notification) survive the Activity going to
// the background or being destroyed - a plain Activity-scoped coroutine
// dies with the Activity, which is exactly what this exists to fix.
//
// Notification approach: a standard NotificationCompat ongoing notification
// with a determinate setProgress() bar, IMPORTANCE_LOW / silent channel, on
// minSdk 24 through the current compileSdk 37 - this is the well-supported,
// broadly-compatible Android mechanism for "show ongoing task progress in
// the status bar", and stays the notification shown on every OS version.
//
// On top of that, every notification here also requests promotion to an
// Android 16 (API 36) "Live Update" via
// NotificationCompat.Builder#setRequestPromotedOngoing(true) - this is the
// actual, confirmed mechanism behind Samsung One UI's Now Bar for
// third-party apps as of One UI 8 (which integrates Now Bar directly with
// Android's platform Live Updates API rather than gating it behind a
// Samsung-only allowlist or a hidden beta flag). Corrected understanding
// vs. an earlier assumption in this codebase: setRequestPromotedOngoing()
// shipped in androidx.core 1.17.0 STABLE in August 2025 (this project is on
// 1.19.0 now), not stuck in alpha - so this is a safe, non-experimental
// dependency bump.
//
// Requirements for promotion to actually take effect - corrected AGAIN
// after live on-device testing (adb dumpsys notification --noredact on a
// real S23) showed mIsPromotion=false despite the permission being granted,
// the AppOp being allowed, and android.requestPromotedOngoing=true/
// PROMOTED_ONGOING flag both present. developer.android.com's "Create live
// update notifications" page claims colorized must NOT be true - that page
// is simply wrong (or describes a different/older gate). The real,
// ground-truth check is Notification#hasPromotableCharacteristics() in
// AOSP frameworks/base (core/java/android/app/Notification.java, current
// main branch):
//
//   public boolean hasPromotableCharacteristics() {
//       return isColorizedRequested()
//               && isOngoingEvent()
//               && hasTitle()
//               && !isGroupSummary()
//               && !containsCustomViews()
//               && hasPromotableStyle();
//   }
//
// where isColorizedRequested() is just `extras.getBoolean(EXTRA_COLORIZED)`
// - i.e. whether the notification called setColorized(true) at all, not
// whether it's actually rendered colorized (that additionally needs FGS/
// USE_COLORIZED_NOTIFICATIONS/already-promoted, per isColorized()). Our
// notification never called setColorized(true), so isColorizedRequested()
// was false, so hasPromotableCharacteristics() - and therefore
// mIsPromotion - was false regardless of everything else being correct.
// hasPromotableStyle() confirms a plain/no-style builder (our case) is
// fine: notificationStyle == null is explicitly allowed alongside
// BigPictureStyle/BigTextStyle/CallStyle/ProgressStyle, so ProgressStyle
// was never actually required.
//
// Fix: add setColorized(true) (+ an explicit setColor(), since a colorized
// notification with no color falls back to a generic system tint) to the
// progress notification only - the one/only notification that also calls
// setRequestPromotedOngoing(true). setColorized(true) on a foreground
// service's notification doesn't need the USE_COLORIZED_NOTIFICATIONS
// permission to be *requested*; the platform additionally grants FGS
// notifications leeway to actually render colorized (isFgsOrUij() in
// isColorized()), so this is safe to call unconditionally here.
//
// Other requirements, all already satisfied:
//   - android.permission.POST_PROMOTED_NOTIFICATIONS declared in the
//     manifest (non-runtime, no prompt).
//   - setOngoing(true) (already set on the progress notification).
//   - contentTitle set.
//   - no custom RemoteViews, not a group summary.
//   - channel importance above IMPORTANCE_MIN (this channel is
//     IMPORTANCE_LOW, which qualifies per both the docs and the source -
//     hasPromotableCharacteristics() itself has no importance check at
//     all; channel importance is a *separate*, additional gate enforced
//     elsewhere in NotificationManagerService, not in this method).
// setRequestPromotedOngoing() is a no-op extra on pre-API-36 devices / on
// launchers that don't understand it, so it's called unconditionally as a
// safe superset of the existing notification - there's no separate
// non-promoted code path to fall back to, because none is needed: an
// unsupported OS or launcher just ignores the extra and shows the exact
// same NotificationCompat notification as before this change.
class ScanService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var scanJob: Job? = null
    private var lastNotifyAtMs = 0L

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_START_SCAN) {
            startScanIfNeeded()
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?) = null

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            SCAN_NOTIFICATION_CHANNEL_ID,
            "Сканирование прокси",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Прогресс массового сканирования MTProto-прокси"
            setSound(null, null)
        }
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    private fun contentPendingIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getActivity(this, 0, intent, flags)
    }

    private fun buildProgressNotification(checked: Int, total: Int, statusLine: String?): Notification {
        val contentText = when {
            total > 0 -> "Проверено $checked/$total"
            !statusLine.isNullOrBlank() -> statusLine
            else -> "Подготовка..."
        }
        return NotificationCompat.Builder(this, SCAN_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("Сканирование прокси")
            .setContentText(contentText)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setProgress(total, checked, total <= 0)
            .setContentIntent(contentPendingIntent())
            // Compact chip text for Live Update surfaces (e.g. Samsung Now
            // Bar) that render a short status alongside/instead of the full
            // contentText - see the class doc for why this is safe to
            // request unconditionally.
            .apply { if (total > 0) setShortCriticalText("$checked/$total") }
            .setRequestPromotedOngoing(true)
            // Required for Notification#hasPromotableCharacteristics() to
            // return true (see the class doc above) - without this the
            // system silently refuses to promote the notification
            // (mIsPromotion stays false) no matter what else is set.
            .setColorized(true)
            .setColor(TG_ACCENT_COLOR)
            .build()
    }

    private fun buildCompletionNotification(aliveCount: Int, totalChecked: Int): Notification {
        return NotificationCompat.Builder(this, SCAN_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("Сканирование завершено")
            .setContentText("Готово: $aliveCount из $totalChecked живы")
            .setOngoing(false)
            .setAutoCancel(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(contentPendingIntent())
            .build()
    }

    private fun buildAbortedNotification(message: String): Notification {
        return NotificationCompat.Builder(this, SCAN_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("Сканирование прервано")
            .setContentText(message)
            .setOngoing(false)
            .setAutoCancel(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(contentPendingIntent())
            .build()
    }

    // POST_NOTIFICATIONS (API 33+) is only requested best-effort from the
    // Activity - the scan must never depend on it being granted, so every
    // notify() here is wrapped: without the permission this just silently
    // shows nothing while the scan itself keeps running exactly as normal.
    private fun postProgressNotificationThrottled(checked: Int, total: Int, statusLine: String?) {
        val now = android.os.SystemClock.elapsedRealtime()
        val isFinal = total > 0 && checked >= total
        if (!isFinal && now - lastNotifyAtMs < NOTIFICATION_THROTTLE_MS) return
        lastNotifyAtMs = now
        try {
            NotificationManagerCompat.from(this).notify(SCAN_NOTIFICATION_ID, buildProgressNotification(checked, total, statusLine))
        } catch (e: Throwable) {
            android.util.Log.e(SCAN_SERVICE_TAG, "progress notify() failed: ${e.message}", e)
        }
    }

    private fun postFinalNotification(notification: Notification) {
        try {
            NotificationManagerCompat.from(this).notify(SCAN_NOTIFICATION_ID, notification)
        } catch (e: Throwable) {
            android.util.Log.e(SCAN_SERVICE_TAG, "final notify() failed: ${e.message}", e)
        }
    }

    private fun startScanIfNeeded() {
        if (scanJob?.isActive == true) return // a scan is already running - ignore a duplicate start request

        val filesDirPath = filesDir.absolutePath
        ScanBridge.update {
            it.copy(
                isScanning = true,
                checked = 0,
                total = 0,
                statusLine = "Загружаю список кандидатов...",
                aliveResults = emptyList(),
                everScanned = true,
            )
        }

        try {
            ServiceCompat.startForeground(
                this,
                SCAN_NOTIFICATION_ID,
                buildProgressNotification(0, 0, null),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } catch (e: Throwable) {
            android.util.Log.e(SCAN_SERVICE_TAG, "startForeground failed: ${e.message}", e)
        }

        scanJob = serviceScope.launch {
            val liveAlive = mutableListOf<AliveHit>()
            var finalNotificationPosted = false
            try {
                runMassScan(
                    filesDirPath,
                    onStatus = { status ->
                        ScanBridge.update { it.copy(statusLine = status) }
                    },
                    onProgress = { checkedCount, total ->
                        ScanBridge.update { it.copy(checked = checkedCount, total = total) }
                        postProgressNotificationThrottled(checkedCount, total, ScanBridge.state.value.statusLine)
                    },
                    onAlive = { hit ->
                        liveAlive.add(hit)
                        ScanBridge.update { it.copy(aliveResults = liveAlive.toList()) }
                    },
                    onComplete = { totalChecked ->
                        saveLastScanResults(filesDirPath, totalChecked, liveAlive.toList())
                        val info = "Последнее сканирование: ${liveAlive.size} из $totalChecked живы " +
                            "(${formatLastScanTimestamp(System.currentTimeMillis())})"
                        ScanBridge.update { it.copy(totalCheckedLast = totalChecked, lastScanInfo = info) }
                        postFinalNotification(buildCompletionNotification(liveAlive.size, totalChecked))
                        finalNotificationPosted = true
                    },
                )
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_SERVICE_TAG, "runMassScan crashed: ${e::class.simpleName}: ${e.message}", e)
                val message = "${e::class.simpleName}: ${e.message}"
                ScanBridge.update { it.copy(statusLine = "FAIL: сканирование прервано — $message") }
                postFinalNotification(buildAbortedNotification(message))
                finalNotificationPosted = true
            } finally {
                ScanBridge.update { it.copy(isScanning = false) }
                if (!finalNotificationPosted) {
                    // runMassScan can return early (candidate list fetch failed)
                    // without ever calling onComplete AND without throwing - it
                    // catches that internally and just returns after onStatus().
                    // Without this, the notification would be stuck showing
                    // stale "ongoing" progress forever.
                    val fallbackMessage = ScanBridge.state.value.statusLine ?: "сканирование прервано"
                    postFinalNotification(buildAbortedNotification(fallbackMessage))
                }
                try {
                    ServiceCompat.stopForeground(this@ScanService, ServiceCompat.STOP_FOREGROUND_DETACH)
                } catch (e: Throwable) {
                    android.util.Log.e(SCAN_SERVICE_TAG, "stopForeground failed: ${e.message}", e)
                }
                stopSelf()
            }
        }
    }
}
