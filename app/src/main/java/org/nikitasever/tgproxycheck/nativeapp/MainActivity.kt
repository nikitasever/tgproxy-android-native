package org.nikitasever.tgproxycheck.nativeapp

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.Divider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import java.io.File
import dev.g000sha256.tdl.TdlClient
import dev.g000sha256.tdl.TdlResult
import dev.g000sha256.tdl.dto.AuthorizationStateClosed
import dev.g000sha256.tdl.dto.ConnectionState
import dev.g000sha256.tdl.dto.ConnectionStateReady
import dev.g000sha256.tdl.dto.Proxy
import dev.g000sha256.tdl.dto.ProxyType
import dev.g000sha256.tdl.dto.ProxyTypeMtproto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

// The server's own endpoints (self-signed cert, same trust-all approach the
// Python checker already uses server-side for its own requests).
private const val RESULTS_URL =
    "https://77.110.98.222:8765/results.json?token=M2Pxr2BUvkbrS-9CSu40D2CFwwgY0rxY"
private const val CANDIDATES_URL =
    "https://77.110.98.222:8765/candidates.json?token=M2Pxr2BUvkbrS-9CSu40D2CFwwgY0rxY"

// Proxies masquerading (via FakeTLS) as one of these can't be blocked wholesale by an
// ISP without breaking huge amounts of legitimate traffic, so they survive targeted DPI
// blocking far better than ones fronting some random low-traffic filler domain — see
// domain_priority.py on the server for how this was discovered.
private val PROTECTED_DOMAIN_KEYWORDS = listOf(
    "google", "gstatic", "youtube", "ytimg", "gvt1", "gvt2",
    "yandex", "vk.com", "vk.ru", "mail.ru",
    "cloudflare", "cloudflare-dns",
    "amazon", "amazonaws", "awsstatic",
    "microsoft", "azure", "windows", "office",
    "apple", "icloud",
    "whatsapp", "instagram", "facebook", "fbcdn",
    "akamai", "akamaized", "fastly", "cloudfront",
    "bing", "wikipedia", "wikimedia",
)

// Same protected-domain concept, but split into rough geographic buckets for
// grouping results in the UI - kept as a Kotlin port of the same mapping used
// server-side in domain_priority.py (DOMAIN_CATEGORIES). Not taxonomically
// perfect on purpose - one bucket per keyword is good enough here.
private val DOMAIN_CATEGORIES: List<Pair<String, List<String>>> = listOf(
    "RU" to listOf("yandex", "vk.com", "vk.ru", "mail.ru", "gosuslugi"),
    "EU" to listOf(
        "google", "gstatic", "youtube", "ytimg", "gvt1", "gvt2",
        "cloudflare", "cloudflare-dns",
        "amazon", "amazonaws", "awsstatic",
        "microsoft", "azure", "windows", "office",
        "apple", "icloud",
    ),
    "US" to listOf(
        "whatsapp", "instagram", "facebook", "fbcdn",
        "akamai", "akamaized", "fastly", "cloudfront",
        "bing",
    ),
    // No strong signal yet in the current source pool - left ready in case
    // Asian CDN-fronted proxies show up later.
    "Asia" to listOf("alibaba", "aliyun", "tencent", "baidu", "wechat", "weibo"),
)

private val CATEGORY_ORDER = listOf("RU", "EU", "US", "Asia", "Other")

// Small decorative glyph shown per category chip - purely cosmetic, no effect
// on classification/business logic.
private fun categoryEmoji(category: String): String = when (category) {
    "RU" -> "🇷🇺"
    "EU" -> "🇪🇺"
    "US" -> "🇺🇸"
    "Asia" -> "🌏"
    else -> "🌐"
}

private fun classifyDomain(domain: String?): String {
    if (domain.isNullOrEmpty()) return "Other"
    for ((category, keywords) in DOMAIN_CATEGORIES) {
        if (keywords.any { domain.contains(it) }) return category
    }
    return "Other"
}

// The server verifies from its own VPS/datacenter IP, which some MTProxy operators
// block outright (a common anti-scanning measure) — confirmed by hand: proxies the
// phone connects to fine sometimes fail the server's own from-VPS check. So its
// "verified" list under-counts what actually works for a real device and can't be
// trusted as the pool to draw from; the raw, unfiltered candidates.json pool (tested
// live from this phone) is the only reliable ground truth.
private const val REGULAR_FILL_LIMIT = 350
// History: 16 (0.7.0) -> crashed ~49/448. 10 (0.7.1, "catch Throwable + delete
// per-candidate dirs") -> crashed ~82/450, just later, not fixed. 6 (0.7.2,
// "wait for AuthorizationStateClosed before tearing down") -> crashed ~96/450,
// again just later. All three treated symptoms of the same root cause: a
// brand-new native TDLib client was being created AND destroyed for every
// single one of ~450 candidates, and dev.g000sha256:tdl-coroutines-android's
// own TdlServiceLocator/TdlEngine show the receiver thread, sender thread and
// native ClientManager are process-wide singletons - so every teardown (even a
// "clean" one) adds to a monotonically growing amount of native bookkeeping
// that nothing before 0.8.0 ever gave back. 0.8.0 removes the per-candidate
// create/destroy cycle entirely (see runPoolWorker below): a fixed pool of
// SCAN_CONCURRENCY clients is created ONCE and reused for the whole scan, so
// this number is now genuinely just "how many proxies are dialed at once",
// not a mitigation for a leak.
private const val SCAN_CONCURRENCY = 6
private const val PER_PROXY_TIMEOUT_MS = 6_000L
// How long to wait for TDLib to confirm a client's native shutdown
// (AuthorizationStateClosed) after close() is requested, before giving up and
// deleting its db directory anyway. close() itself only enqueues the shutdown -
// see the doc comment on runPoolWorker.
private const val CLOSE_TIMEOUT_MS = 5_000L
private const val SCAN_TAG = "TgProxyScan"

data class Candidate(
    val server: String,
    val port: Int,
    val secret: String,
    val mtprotoMs: Int,
    val isProtectedDomain: Boolean,
    val category: String,
)

private fun decodeFakeTlsDomain(secret: String): String? {
    val hex = secret.trim().lowercase()
        .takeIf { it.matches(Regex("[0-9a-f]+")) && it.length % 2 == 0 }
        ?: return null
    if (!hex.startsWith("ee") || hex.length <= 2 + 32) return null
    val domainHex = hex.substring(2 + 32)
    if (domainHex.isEmpty() || domainHex.length % 2 != 0) return null
    return try {
        val bytes = ByteArray(domainHex.length / 2) { i ->
            domainHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        val domain = String(bytes, Charsets.US_ASCII)
        if (domain.any { it.code < 32 || it.code >= 127 }) null else domain
    } catch (e: Exception) {
        null
    }
}

private fun isProtectedDomain(domain: String?): Boolean {
    if (domain.isNullOrEmpty()) return false
    return PROTECTED_DOMAIN_KEYWORDS.any { domain.contains(it) }
}

// tg:// is Telegram's own scheme, handled only by the Telegram app itself - unlike
// https://t.me/..., which Android may route to a browser instead of the app.
private fun Candidate.toTelegramProxyUrl(): String =
    "tg://proxy?server=$server&port=$port&secret=$secret"

// Root cause of the v0.8.0 crash (confirmed via a real adb logcat capture, not
// guesswork this time): `IllegalArgumentException: Key "rec-mtproto.yet.ac:443"
// was already used` inside the results LazyColumn. Two independent gaps let the
// same physical proxy end up as two AliveHit entries with an identical rendered
// key:
//  1. runMassScan's old dedup key was a bare Triple(server, port, secret) - an
//     exact, case-sensitive string comparison. results.json (server-verified)
//     and candidates.json (raw) can list the same proxy with the secret hex in
//     a different case/whitespace form, so distinctBy let both through as
//     "different" candidates, both got scanned, both came back alive.
//  2. Separately, the old "⭐ Рекомендуем" LazyColumn key was
//     "rec-$server:$port" - it never included the secret at all, so even two
//     *legitimately* distinct proxies (an MTProxy server serving more than one
//     secret on the same port, which is normal MTProto server behaviour) would
//     collide there.
// This helper is now the one place that defines "is this the same proxy" -
// normalized (trimmed, lowercased) server+port+secret - and is used both to
// dedup the candidate pool before scanning (so the same proxy is never
// scanned twice) and to build render keys (so two genuinely different
// same-server:port proxies never collide either).
private fun proxyIdentityKey(c: Candidate): String =
    "${c.server.trim().lowercase()}:${c.port}:${c.secret.trim().lowercase()}"

// downloadKbps/uploadKbps used to be sampled via TDLib's getNetworkStatistics()
// right after ConnectionStateReady. That was removed in 0.7.1: TDLib's
// NetworkStatistics only ever accumulates entries of type
// NetworkStatisticsEntryCall (voice/video calls) or NetworkStatisticsEntryFile
// (file up/downloads) - see td_api.tql's networkStatisticsEntryCall /
// networkStatisticsEntryFile, the only two variants of NetworkStatisticsEntry.
// This mass-scan never logs in and never transfers a file or places a call, so
// there is structurally nothing for TDLib to record: the entries list is
// always empty and the metric always reads 0.0/0.0, regardless of
// onlyCurrent or sampling timing - it's not a race, the data source just
// doesn't cover pre-auth handshake bytes. Rather than ship a metric that
// always shows zero, it was removed; pingMs (time from adding the proxy to
// ConnectionStateReady) remains the honest signal for "how fast does this
// proxy connect". Fields kept (always null now) so old persisted
// last_scan_results.json files with real values still load without a schema
// change.
data class AliveHit(
    val candidate: Candidate,
    val pingMs: Long,
    val downloadKbps: Double?,
    val uploadKbps: Double?,
)

// Lower is "better" (sorted ascending), so it composes with plain ping ranking:
// with no speed data it's just ping in ms. Measured speed and protected-domain
// status pull the effective rank down (protected domains survive DPI far
// better - see PROTECTED_DOMAIN_KEYWORDS above - so they're worth ranking
// higher even at equal ping). Weights are deliberately rough; this is a rough
// "which one would I actually pick" heuristic, not a precise scoring model.
private fun AliveHit.recommendScore(): Double {
    val speedBonus = (downloadKbps ?: 0.0) * 20.0 + (uploadKbps ?: 0.0) * 10.0
    val protectedBonus = if (candidate.isProtectedDomain) 500.0 else 0.0
    return pingMs.toDouble() - speedBonus - protectedBonus
}

private const val LAST_SCAN_FILE_NAME = "last_scan_results.json"

data class LastScanSnapshot(val timestampMs: Long, val totalChecked: Int, val hits: List<AliveHit>)

// Manual JSON (org.json, already used elsewhere in this file) rather than pulling
// in a new serialization dependency for one small file.
internal fun saveLastScanResults(filesDirPath: String, totalChecked: Int, hits: List<AliveHit>) {
    try {
        val root = org.json.JSONObject()
        root.put("timestampMs", System.currentTimeMillis())
        root.put("totalChecked", totalChecked)
        val resultsJson = JSONArray()
        hits.forEach { hit ->
            val o = org.json.JSONObject()
            o.put("server", hit.candidate.server)
            o.put("port", hit.candidate.port)
            o.put("secret", hit.candidate.secret)
            o.put("mtprotoMs", hit.candidate.mtprotoMs)
            o.put("isProtectedDomain", hit.candidate.isProtectedDomain)
            o.put("category", hit.candidate.category)
            o.put("pingMs", hit.pingMs)
            if (hit.downloadKbps != null) o.put("downloadKbps", hit.downloadKbps)
            if (hit.uploadKbps != null) o.put("uploadKbps", hit.uploadKbps)
            resultsJson.put(o)
        }
        root.put("results", resultsJson)
        // Write to a temp file and rename over the real one so a process death
        // mid-write (e.g. the OOM scenario documented on checkViaConnection)
        // can never leave a half-written/corrupt last_scan_results.json behind
        // for the next cold start to choke on.
        val target = File(filesDirPath, LAST_SCAN_FILE_NAME)
        val tmp = File(filesDirPath, "$LAST_SCAN_FILE_NAME.tmp")
        tmp.writeText(root.toString())
        if (!tmp.renameTo(target)) {
            // renameTo can fail across some filesystems/edge cases; fall back to a
            // direct write rather than silently losing the scan results.
            target.writeText(root.toString())
            tmp.delete()
        }
    } catch (e: Throwable) {
        android.util.Log.e(UPDATE_CHECK_TAG, "saveLastScanResults failed: ${e.message}", e)
    }
}

private fun loadLastScanResults(filesDirPath: String): LastScanSnapshot? {
    return try {
        val file = File(filesDirPath, LAST_SCAN_FILE_NAME)
        if (!file.exists()) return null
        val root = org.json.JSONObject(file.readText())
        val resultsJson = root.getJSONArray("results")
        val hits = (0 until resultsJson.length()).map { i ->
            val o = resultsJson.getJSONObject(i)
            AliveHit(
                candidate = Candidate(
                    server = o.getString("server"),
                    port = o.getInt("port"),
                    secret = o.getString("secret"),
                    mtprotoMs = o.optInt("mtprotoMs", Int.MAX_VALUE),
                    isProtectedDomain = o.getBoolean("isProtectedDomain"),
                    category = o.getString("category"),
                ),
                pingMs = o.getLong("pingMs"),
                downloadKbps = if (o.has("downloadKbps")) o.getDouble("downloadKbps") else null,
                uploadKbps = if (o.has("uploadKbps")) o.getDouble("uploadKbps") else null,
            )
        }
        LastScanSnapshot(
            timestampMs = root.getLong("timestampMs"),
            totalChecked = root.optInt("totalChecked", hits.size),
            hits = hits,
        )
    } catch (e: Throwable) {
        android.util.Log.e(UPDATE_CHECK_TAG, "loadLastScanResults failed: ${e.message}", e)
        null
    }
}

private const val GITHUB_LATEST_RELEASE_URL =
    "https://api.github.com/repos/nikitasever/tgproxy-android-native/releases/latest"

data class UpdateInfo(val version: String, val downloadUrl: String)

private const val UPDATE_CHECK_TAG = "TgProxyUpdateCheck"

// Distinct outcomes instead of a bare nullable: "no update" and "check failed"
// look identical to the user if collapsed into one null, which is exactly how
// the previous private-repo-404 bug went unnoticed (unauthenticated GitHub API
// calls to a private repo 404 - not 403 - and the old bare catch swallowed that
// silently with no logging). Keeping these separate, and logging failures via
// Log.e, means a regression like that is visible next time instead of silent.
sealed class UpdateCheckResult {
    data class Available(val info: UpdateInfo) : UpdateCheckResult()
    object UpToDate : UpdateCheckResult()
    data class Error(val message: String) : UpdateCheckResult()
}

// Parses the "major.minor.patch" numeric prefix of a version string, ignoring
// any "-native-poc"-style suffix. Missing/non-numeric components default to 0
// rather than throwing, so a malformed tag_name degrades to "0.0.0" instead of
// crashing the update check.
private fun parseVersionParts(version: String): Triple<Int, Int, Int> {
    val core = version.substringBefore('-')
    val parts = core.split(".").map { it.toIntOrNull() ?: 0 }
    return Triple(parts.getOrElse(0) { 0 }, parts.getOrElse(1) { 0 }, parts.getOrElse(2) { 0 })
}

// Component-wise numeric comparison (NOT string comparison - "0.9.0" must not
// compare greater than "0.10.0"). Returns true only if `remote` is strictly
// newer than `local`; equal or older versions (including exact byte-for-byte
// re-releases of the same tag) are never reported as an update. This is what
// closed the bug where a strictly OLDER already-superseded release (e.g.
// v0.10.2) got offered as an "update" over a manually-installed newer local
// build (e.g. 0.10.3) purely because the old code did `tag != current` instead
// of an actual newer-than check.
internal fun isVersionNewer(remote: String, local: String): Boolean {
    val (rMajor, rMinor, rPatch) = parseVersionParts(remote)
    val (lMajor, lMinor, lPatch) = parseVersionParts(local)
    if (rMajor != lMajor) return rMajor > lMajor
    if (rMinor != lMinor) return rMinor > lMinor
    return rPatch > lPatch
}

private suspend fun checkForUpdate(): UpdateCheckResult = withContext(Dispatchers.IO) {
    try {
        val connection = java.net.URL(GITHUB_LATEST_RELEASE_URL).openConnection() as HttpsURLConnection
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000

        val responseCode = connection.responseCode
        if (responseCode !in 200..299) {
            val errorBody = try {
                connection.errorStream?.bufferedReader()?.use { it.readText() }
            } catch (e: Exception) {
                null
            }
            val message = "HTTP $responseCode${errorBody?.let { " — $it" } ?: ""}"
            android.util.Log.e(UPDATE_CHECK_TAG, "checkForUpdate failed: $message")
            return@withContext UpdateCheckResult.Error(message)
        }

        val body = connection.inputStream.bufferedReader().use { it.readText() }
        val root = org.json.JSONObject(body)
        val tagName = root.getString("tag_name").removePrefix("v")
        if (!isVersionNewer(remote = tagName, local = BuildConfig.VERSION_NAME)) {
            return@withContext UpdateCheckResult.UpToDate
        }

        val assets = root.getJSONArray("assets")
        var downloadUrl: String? = null
        for (i in 0 until assets.length()) {
            val asset = assets.getJSONObject(i)
            if (asset.getString("name") == "app-debug.apk") {
                downloadUrl = asset.getString("browser_download_url")
                break
            }
        }
        if (downloadUrl == null) {
            val message = "release $tagName has no app-debug.apk asset"
            android.util.Log.e(UPDATE_CHECK_TAG, "checkForUpdate failed: $message")
            return@withContext UpdateCheckResult.Error(message)
        }
        UpdateCheckResult.Available(UpdateInfo(version = tagName, downloadUrl = downloadUrl))
    } catch (e: Exception) {
        val message = "${e::class.simpleName}: ${e.message}"
        android.util.Log.e(UPDATE_CHECK_TAG, "checkForUpdate failed: $message", e)
        UpdateCheckResult.Error(message)
    }
}

// Overall wall-clock cap on the download step, separate from the per-socket-op
// connect/read timeouts inside downloadApk() - see the call site in
// ProxyCheckScreen for why this is needed to prevent an indefinite hang.
private const val APK_DOWNLOAD_TIMEOUT_MS = 120_000L

private suspend fun downloadApk(url: String, destFile: File): Unit = withContext(Dispatchers.IO) {
    val connection = java.net.URL(url).openConnection() as HttpsURLConnection
    connection.connectTimeout = 15_000
    connection.readTimeout = 30_000
    connection.instanceFollowRedirects = true
    connection.inputStream.use { input ->
        destFile.outputStream().use { output -> input.copyTo(output) }
    }
}

// Telegram-dark-mode-flavoured Material3 palette. Not the stock Material dark
// scheme - background/surface/primary are pinned to specific hex values so the
// app reads as "Telegram dark", not "default Compose dark theme".
private val TgBackground = Color(0xFF0E1621)
private val TgSurface = Color(0xFF17212B)
private val TgSurfaceVariant = Color(0xFF1F2C38)
private val TgAccent = Color(0xFF2AABEE)
private val TgAccentDark = Color(0xFF229ED9)
private val TgOnBackground = Color(0xFFE4E9EE)
private val TgOnSurfaceMuted = Color(0xFF8A97A3)
private val TgError = Color(0xFFF44336)

private val TgColorScheme: ColorScheme = darkColorScheme(
    primary = TgAccent,
    onPrimary = Color.White,
    secondary = TgAccentDark,
    onSecondary = Color.White,
    background = TgBackground,
    onBackground = TgOnBackground,
    surface = TgSurface,
    onSurface = TgOnBackground,
    surfaceVariant = TgSurfaceVariant,
    onSurfaceVariant = TgOnSurfaceMuted,
    error = TgError,
    onError = Color.White,
)

// Ping thresholds for the colored badge - green/amber/red. Typical values seen
// over hundreds of scanned MTProxy candidates from a real device run from well
// under a second (fast, nearby/well-peered) up past 2-3s right before the
// PER_PROXY_TIMEOUT_MS cutoff (slow/marginal), so 800ms/2000ms splits the
// observed range into three roughly meaningful bands rather than being
// arbitrary round numbers.
private fun pingColor(pingMs: Long): Color = when {
    pingMs < 800 -> Color(0xFF4CAF50)
    pingMs < 2000 -> Color(0xFFFFC107)
    else -> Color(0xFFF44336)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = TgColorScheme) {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    ProxyCheckScreen(filesDir.absolutePath)
                }
            }
        }
    }
}

internal fun formatLastScanTimestamp(timestampMs: Long): String {
    val fmt = java.text.SimpleDateFormat("H:mm, d.M.yy", java.util.Locale.getDefault())
    return fmt.format(java.util.Date(timestampMs))
}

@Composable
fun ProxyCheckScreen(filesDirPath: String) {
    val scope = remember { CoroutineScope(Dispatchers.Main) }
    val context = LocalContext.current

    var updateInfo by remember { mutableStateOf<UpdateInfo?>(null) }
    var updateStatus by remember { mutableStateOf<String?>(null) }
    var updateCheckError by remember { mutableStateOf<String?>(null) }

    // The scan itself now runs inside ScanService (a foreground Service) so it
    // - and its status-bar progress notification - survive this Activity going
    // to the background or being recreated. ScanBridge is the process-wide
    // StateFlow both this screen and the Service read/write; this screen no
    // longer owns the scan state directly, it just mirrors the bridge.
    val uiState by ScanBridge.state.collectAsState()
    val aliveResults = uiState.aliveResults
    val lastScanInfo = uiState.lastScanInfo
    val everScanned = uiState.everScanned
    val isScanning = uiState.isScanning
    val scanChecked = uiState.checked
    val scanTotal = uiState.total
    val statusLine = uiState.statusLine

    // POST_NOTIFICATIONS (Android 13+) is best-effort only: if denied, the scan
    // still runs exactly the same via ScanService, it just won't be able to
    // show status-bar progress. No result handling needed beyond letting the
    // system remember the choice - ScanService's own notify() calls are all
    // wrapped defensively for exactly this "permission not granted" case.
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* granted or not, the scan proceeds regardless */ }

    // Root cause of the "устанавливаю..." hang that never recovered: the old code
    // fired the install intent with a bare context.startActivity() and never
    // touched updateStatus again on the success path - only the catch block reset
    // it, so a *successful* launch of the system package-installer UI (the
    // overwhelmingly common case) left the banner stuck on "устанавливаю..."
    // forever with no way back to idle. Launching it through an ActivityResult
    // contract instead means this callback fires when the installer activity
    // returns control to us (installed, cancelled, or failed) and unconditionally
    // clears the state - there is no code path anymore that leaves the UI wedged.
    val installLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { updateStatus = null }

    LaunchedEffect(Unit) {
        when (val result = checkForUpdate()) {
            is UpdateCheckResult.Available -> updateInfo = result.info
            UpdateCheckResult.UpToDate -> Unit
            is UpdateCheckResult.Error -> updateCheckError = result.message
        }

        // Load the previous scan's results immediately on cold start, before any
        // new scan runs, so the user isn't staring at an empty screen while a
        // fresh scan (which can take a while over hundreds of candidates) runs.
        // seedIfEmpty is a no-op if the bridge already holds real state (e.g.
        // this Activity was merely recreated while ScanService kept running).
        val snapshot = loadLastScanResults(filesDirPath)
        if (snapshot != null) {
            ScanBridge.seedIfEmpty(
                ScanUiState(
                    aliveResults = snapshot.hits,
                    totalCheckedLast = snapshot.totalChecked,
                    everScanned = true,
                    lastScanInfo = "Последнее сканирование: ${snapshot.hits.size} из ${snapshot.totalChecked} " +
                        "живы (${formatLastScanTimestamp(snapshot.timestampMs)})",
                )
            )
        }
    }

    fun startScan() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val intent = Intent(context, ScanService::class.java).setAction(ACTION_START_SCAN)
        ContextCompat.startForegroundService(context, intent)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(20.dp)
    ) {
        if (updateInfo == null && updateCheckError != null) {
            Text(
                text = "Не удалось проверить обновление: $updateCheckError",
                color = TgOnSurfaceMuted,
                fontSize = 12.sp,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }
        updateInfo?.let { info ->
            Card(
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = TgSurfaceVariant),
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Доступно обновление: v${info.version}",
                        color = MaterialTheme.colorScheme.onBackground,
                        fontWeight = FontWeight.SemiBold,
                    )
                    updateStatus?.let {
                        Text(text = it, color = TgOnSurfaceMuted, fontSize = 12.sp, modifier = Modifier.padding(top = 2.dp))
                    }
                    Button(
                        modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = TgAccent, contentColor = Color.White),
                        onClick = {
                            val needsInstallPermission = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O &&
                                !context.packageManager.canRequestPackageInstalls()
                            if (needsInstallPermission) {
                                updateStatus = "нужно разрешение на установку — открываю настройки"
                                context.startActivity(
                                    Intent(
                                        android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                        Uri.parse("package:${context.packageName}"),
                                    )
                                )
                                return@Button
                            }
                            scope.launch {
                                updateStatus = "скачиваю..."
                                try {
                                    val updatesDir = File(context.cacheDir, "updates").apply { mkdirs() }
                                    val apkFile = File(updatesDir, "update.apk")
                                    // Bounded overall download time: the connection's own
                                    // connect/read timeouts only bound a single socket
                                    // operation, not the whole transfer, so a slow trickle
                                    // could otherwise stall here indefinitely. On timeout
                                    // this throws TimeoutCancellationException, which the
                                    // catch below turns into a visible FAIL instead of an
                                    // unbounded hang.
                                    withTimeout(APK_DOWNLOAD_TIMEOUT_MS) {
                                        downloadApk(info.downloadUrl, apkFile)
                                    }
                                    updateStatus = "устанавливаю..."
                                    val uri = FileProvider.getUriForFile(
                                        context,
                                        "org.nikitasever.tgproxycheck.nativeapp.fileprovider",
                                        apkFile,
                                    )
                                    val installIntent = Intent(Intent.ACTION_VIEW).apply {
                                        setDataAndType(uri, "application/vnd.android.package-archive")
                                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                    }
                                    // Launched via the ActivityResult contract (not a bare
                                    // startActivity) so installLauncher's callback above can
                                    // reset updateStatus once the installer returns control
                                    // to us - see the doc comment on installLauncher for why
                                    // that's the actual fix for the indefinite hang.
                                    installLauncher.launch(installIntent)
                                } catch (e: Exception) {
                                    updateStatus = "FAIL: ${e::class.simpleName}: ${e.message}"
                                }
                            }
                        },
                    ) {
                        Text("Обновить")
                    }
                }
            }
        }

        // Header: active progress bar while scanning, otherwise a rest-state
        // summary of the last completed scan.
        if (isScanning) {
            Column(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                if (scanTotal > 0) {
                    LinearProgressIndicator(
                        progress = { scanChecked.toFloat() / scanTotal.toFloat() },
                        modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                        color = TgAccent,
                        trackColor = TgSurfaceVariant,
                    )
                } else {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                        color = TgAccent,
                        trackColor = TgSurfaceVariant,
                    )
                }
                statusLine?.let {
                    Text(
                        text = it,
                        color = TgOnSurfaceMuted,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }
            }
        } else {
            statusLine?.takeIf { it.startsWith("FAIL") }?.let {
                Text(
                    text = it,
                    color = TgError,
                    fontSize = 12.sp,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
            }
            lastScanInfo?.let { info ->
                Text(
                    text = info,
                    color = TgOnSurfaceMuted,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
            }
        }

        Button(
            modifier = Modifier.fillMaxWidth().height(48.dp),
            enabled = !isScanning,
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = TgAccent,
                contentColor = Color.White,
                disabledContainerColor = TgSurfaceVariant,
                disabledContentColor = TgOnSurfaceMuted,
            ),
            onClick = { startScan() },
        ) {
            if (isScanning) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    color = TgOnSurfaceMuted,
                    strokeWidth = 2.dp,
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    if (scanTotal > 0) "Сканирование… $scanChecked/$scanTotal" else "Сканирование…",
                )
            } else {
                Text("Массовое сканирование")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Belt-and-suspenders dedup (see proxyIdentityKey doc comment): the real
        // fix is scanning each proxy only once (runMassScan's `key()`), but this
        // guards the render layer too in case a stale persisted snapshot and a
        // fresh scan result for the same proxy ever end up coexisting in
        // aliveResults. Keeps the first occurrence (already-added order).
        val dedupedAlive = aliveResults.distinctBy { proxyIdentityKey(it.candidate) }

        // Sort by a combined "how good is this proxy right now" score everywhere:
        // ascending ping as the base signal, pulled down further by measured
        // speed and by protected-domain status (see recommendScore() doc above).
        //
        // Host-diversity cap for Рекомендуем: a single MTProto server can (and in
        // practice does, e.g. mtproto.yet.ac) legitimately serve many distinct
        // secrets on the same server:port - proxyIdentityKey correctly treats
        // each secret as its own AliveHit, so dedupedAlive can contain 8+ entries
        // that are all "the same host" from the user's point of view. Left alone,
        // sortedBy{recommendScore()}.take(8) can fill the entire "recommended"
        // panel with near-identical entries from one prolific host, which reads
        // as a bug ("why are there 8 copies of the same proxy?") even though it
        // isn't one. Fix: collapse to the single best-scoring hit per
        // server:port BEFORE taking the top N, so Рекомендуем is diverse across
        // hosts. Keeps the same recommendScore() ordering/logic otherwise.
        val bestPerHost: List<AliveHit> = dedupedAlive
            .groupBy { "${it.candidate.server.trim().lowercase()}:${it.candidate.port}" }
            .map { (_, hits) -> hits.minBy { it.recommendScore() } }
        val recommended = bestPerHost.sortedBy { it.recommendScore() }.take(8)
        val grouped: Map<String, List<AliveHit>> = dedupedAlive
            .groupBy { it.candidate.category }
            .mapValues { (_, hits) -> hits.sortedBy { it.recommendScore() } }

        fun addToTelegram(hit: AliveHit) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(hit.candidate.toTelegramProxyUrl()))
            context.startActivity(intent)
        }

        if (!isScanning && everScanned && dedupedAlive.isEmpty()) {
            // Scan ran but found nothing alive right now - distinct from the
            // never-scanned empty state below.
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    text = "Живых прокси не найдено в этот раз. Попробуйте ещё раз позже.",
                    color = TgOnSurfaceMuted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 24.dp),
                )
            }
        } else if (!everScanned && !isScanning) {
            EmptyFirstLaunchState()
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                if (recommended.isNotEmpty()) {
                    item(key = "header-recommended") {
                        RecommendedPanel(recommended = recommended, onAdd = ::addToTelegram)
                        Spacer(modifier = Modifier.height(16.dp))
                    }
                }

                for (category in CATEGORY_ORDER) {
                    val hits = grouped[category] ?: continue
                    if (hits.isEmpty()) continue
                    item(key = "header-$category") {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(text = categoryEmoji(category), fontSize = 16.sp)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "$category (${hits.size})",
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onBackground,
                                fontSize = 14.sp,
                            )
                        }
                    }
                    // Key includes the full normalized proxy identity (not just
                    // server:port - see proxyIdentityKey doc comment for why that
                    // alone caused the v0.8.0 crash) PLUS the index as an absolute
                    // safety net: even if some future bug ever produced two
                    // AliveHits with a truly identical identity, the index still
                    // guarantees Compose never sees a duplicate key.
                    itemsIndexed(hits, key = { index, hit -> "cat-$category-$index-${proxyIdentityKey(hit.candidate)}" }) { _, hit ->
                        ProxyCard(hit = hit, onAdd = { addToTelegram(hit) }, modifier = Modifier.padding(bottom = 10.dp))
                    }
                    item(key = "spacer-$category") {
                        Spacer(modifier = Modifier.height(6.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyFirstLaunchState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(text = "🔍", fontSize = 48.sp)
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Нажми, чтобы найти рабочие прокси",
                color = MaterialTheme.colorScheme.onBackground,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Массовое сканирование проверит сотни MTProto-прокси и покажет, какие живы прямо сейчас",
                color = TgOnSurfaceMuted,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 32.dp),
            )
        }
    }
}

@Composable
private fun PingBadge(pingMs: Long) {
    val color = pingColor(pingMs)
    Surface(
        color = color.copy(alpha = 0.16f),
        shape = RoundedCornerShape(8.dp),
    ) {
        Text(
            text = "${pingMs} мс",
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

@Composable
private fun ProtectedDomainChip() {
    Surface(
        color = TgAccent.copy(alpha = 0.16f),
        shape = RoundedCornerShape(8.dp),
    ) {
        Text(
            text = "защищённый домен",
            color = TgAccent,
            // 10sp (down from 11sp) plus maxLines/overflow below is what actually
            // fixes the misaligned rows: at 11sp this chip could wrap to two lines
            // whenever the surrounding row was tight on width (e.g. a long
            // server hostname), which made that specific card's row taller than
            // its neighbours and threw off the visual rhythm of the list even
            // though everything inside the row was still individually centered.
            // Forcing a single line keeps every row's height - and therefore the
            // vertical centering of the emoji/badge/button against it -
            // consistent regardless of server name length.
            fontSize = 10.sp,
            maxLines = 1,
            softWrap = false,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

// Row content shared by both the plain per-category cards and the recommended
// panel (which supplies its own outer background, so the row itself stays
// transparent there).
@Composable
private fun ProxyRowContent(hit: AliveHit, onAdd: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Emoji and button are direct children of the outer CenterVertically Row,
        // so they stay vertically centered against the full row height even on
        // the rare row where the middle Column still ends up taller (e.g. an
        // unusually long server hostname) - see ProtectedDomainChip's doc
        // comment for the other half of this fix (stopping the chip itself from
        // being what made rows inconsistently tall in the first place).
        Text(text = categoryEmoji(hit.candidate.category), fontSize = 18.sp)
        Spacer(modifier = Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "${hit.candidate.server}:${hit.candidate.port}",
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
                color = MaterialTheme.colorScheme.onBackground,
                maxLines = 1,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                PingBadge(hit.pingMs)
                if (hit.candidate.isProtectedDomain) {
                    Spacer(modifier = Modifier.width(6.dp))
                    ProtectedDomainChip()
                }
            }
        }
        Spacer(modifier = Modifier.width(12.dp))
        Button(
            onClick = onAdd,
            shape = RoundedCornerShape(10.dp),
            colors = ButtonDefaults.buttonColors(containerColor = TgAccent, contentColor = Color.White),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 14.dp, vertical = 8.dp),
        ) {
            Text("Добавить", fontSize = 13.sp, maxLines = 1)
        }
    }
}

@Composable
private fun ProxyCard(hit: AliveHit, onAdd: () -> Unit, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = TgSurface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        ProxyRowContent(hit = hit, onAdd = onAdd)
    }
}

// The recommended section gets a visually distinct panel - accent border plus a
// subtle tinted gradient background - so it reads as clearly more important
// than the plain per-category cards below it.
@Composable
private fun RecommendedPanel(recommended: List<AliveHit>, onAdd: (AliveHit) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        border = BorderStroke(1.5.dp, TgAccent),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(TgAccent.copy(alpha = 0.20f), TgAccent.copy(alpha = 0.05f)),
                    )
                ),
        ) {
            Text(
                text = "⭐ Рекомендуем (${recommended.size})",
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
                color = Color.White,
                modifier = Modifier.padding(start = 14.dp, top = 14.dp, bottom = 4.dp),
            )
            recommended.forEachIndexed { index, hit ->
                ProxyRowContent(hit = hit, onAdd = { onAdd(hit) })
                if (index != recommended.lastIndex) {
                    Divider(color = Color.White.copy(alpha = 0.08f), modifier = Modifier.padding(horizontal = 14.dp))
                }
            }
            Spacer(modifier = Modifier.height(6.dp))
        }
    }
}

internal suspend fun runMassScan(
    filesDirPath: String,
    onStatus: (String) -> Unit,
    onProgress: (checked: Int, total: Int) -> Unit,
    onAlive: (AliveHit) -> Unit,
    onComplete: (totalChecked: Int) -> Unit = {},
) {
    val verified: List<Candidate>
    val raw: List<Candidate>
    try {
        verified = fetchJsonCandidates(RESULTS_URL, jsonArrayKey = "proxies")
        raw = fetchJsonCandidates(CANDIDATES_URL, jsonArrayKey = "candidates")
    } catch (e: Exception) {
        onStatus("FAIL: не удалось получить список — ${e::class.simpleName}: ${e.message}")
        return
    }

    // Normalized identity (see proxyIdentityKey doc comment) - NOT a raw
    // case-sensitive Triple(server, port, secret) - so the same physical proxy
    // listed with differently-cased/whitespaced secret hex in results.json vs
    // candidates.json is recognized as one candidate and scanned only once.
    fun key(c: Candidate) = proxyIdentityKey(c)

    // Protected-domain proxies are rare but survive DPI far better, so test every one
    // we can find (server-verified or not). For the rest: server-verified candidates
    // go first (still a decent quality signal), but the raw unfiltered pool fills out
    // the bulk of the run, since the server's own verification under-counts what
    // actually works for a real device.
    val protected = (verified + raw).filter { it.isProtectedDomain }.distinctBy(::key)
    val regularOrdered = (verified.filter { !it.isProtectedDomain }.sortedBy { it.mtprotoMs } +
        raw.filter { !it.isProtectedDomain }).distinctBy(::key)
    val regularFill = regularOrdered.take(REGULAR_FILL_LIMIT)
    val subset = (protected + regularFill).distinctBy(::key)

    onStatus(
        "Кандидатов: ${verified.size} verified + ${raw.size} сырых, " +
            "защищённых доменов: ${protected.size}, проверяю ${subset.size}..."
    )
    onProgress(0, subset.size)

    if (subset.isEmpty()) {
        onStatus("Готово: нет кандидатов для проверки")
        onComplete(0)
        return
    }

    // Plain Int++ from multiple concurrent pool workers (on Dispatchers.Default,
    // so genuinely multi-threaded) is a data race; use atomics so the
    // "Проверено N/M" counter is actually accurate.
    val checked = java.util.concurrent.atomic.AtomicInteger(0)
    val alive = java.util.concurrent.atomic.AtomicInteger(0)

    // Distribute candidates round-robin across the SCAN_CONCURRENCY pool workers
    // (rather than in contiguous blocks) so every worker gets a mix of
    // protected-domain/high-priority and filler candidates, instead of worker 0
    // racing through only the "best" ones while the last worker gets the dregs.
    val chunks = Array(SCAN_CONCURRENCY) { mutableListOf<IndexedValue<Candidate>>() }
    subset.forEachIndexed { index, candidate ->
        chunks[index % SCAN_CONCURRENCY].add(IndexedValue(index, candidate))
    }

    // Pool worker db/files dirs are stable and reused across every candidate a
    // worker processes *within this run* (see runPoolWorker) - but they're
    // wiped clean here, once, at the START of the run, so a stale proxy-list
    // entry or auth-state leftover from a previous scan can never bleed into
    // this one. They must NOT be touched again until the whole run finishes.
    for (workerIndex in 0 until SCAN_CONCURRENCY) {
        File(filesDirPath, "tdlib-pool-$workerIndex").deleteRecursively()
        File(filesDirPath, "tdlib-pool-$workerIndex-files").deleteRecursively()
    }

    // A single candidate throwing used to be able to take the whole scan (and the
    // app) down with it: `async { }` inside `coroutineScope { }` propagates any
    // uncaught exception from a child up through the whole scope, cancelling every
    // other in-flight worker and rethrowing out of runMassScan - and since the
    // caller (scope.launch in ProxyCheckScreen) has no CoroutineExceptionHandler,
    // that crashes the whole app. runPoolWorker/checkOneCandidate catch Throwable
    // internally per-candidate, but this outer catch is a second line of defence
    // in case something throws outside that (e.g. client creation itself) so one
    // bad worker never kills the others.
    coroutineScope {
        (0 until SCAN_CONCURRENCY).map { workerIndex ->
            async {
                try {
                    runPoolWorker(
                        filesDirPath = filesDirPath,
                        workerIndex = workerIndex,
                        assigned = chunks[workerIndex],
                        totalSubset = subset.size,
                        checked = checked,
                        alive = alive,
                        onStatus = onStatus,
                        onProgress = onProgress,
                        onAlive = onAlive,
                    )
                } catch (e: Throwable) {
                    android.util.Log.e(
                        SCAN_TAG,
                        "pool worker #$workerIndex crashed: ${e::class.simpleName}: ${e.message}",
                        e,
                    )
                }
            }
        }.awaitAll()
    }

    onStatus("Готово: ${alive.get()} из ${subset.size} живы прямо сейчас (сервер верифицировал все ${subset.size} ранее)")
    onComplete(subset.size)
}

private data class ConnectResult(val pingMs: Long, val downloadKbps: Double?, val uploadKbps: Double?)

// Result of checking one candidate on a pool worker's persistent client: the
// connect outcome (null = not reachable within the timeout / failed), plus the
// id TDLib assigned this candidate's addProxy call (null if it was never
// successfully added), so the caller knows what to removeProxy() before the
// next candidate.
private class PoolCheckOutcome(val result: ConnectResult?, val proxyId: Int?)

// v0.7.0 (16-way concurrency) crashed at candidate ~49/448. v0.7.1 ("catch
// Throwable + delete per-candidate dirs", 10-way) crashed at ~82/450 - later,
// not fixed. v0.7.2 ("wait for AuthorizationStateClosed before tearing down",
// 6-way) crashed at ~96/450 - later again, still not fixed. All three shared
// one architecture: a brand-new native TDLib client (and on-disk DB) was
// created AND destroyed for every single one of ~450 candidates. Reading
// dev.g000sha256:tdl-coroutines-android 14.0.0's own source
// (TdlServiceLocator.kt, TdlEngine.kt) confirms the receiver thread, sender
// thread and the native ClientManager backing every TdlClient.create() call
// are process-wide singletons - so the real cost here was never "N native
// processes", it was one shared native manager being asked to spin up and
// tear down ~450 separate native Td actors (each with its own socket, sqlite
// db, timers) over a single scan. Even with teardown done "correctly" (close()
// + waiting for AuthorizationStateClosed, as v0.7.2 did), any small
// per-teardown residual cost - a lingering allocation, a not-fully-released fd,
// a growing internal table in ClientManager keyed by client id - accumulates
// roughly linearly across hundreds of create/destroy cycles. That exactly
// matches "crashes later but still crashes" as concurrency/wait-time
// mitigations were tightened three times in a row.
//
// 0.8.0 fix: stop creating a client per candidate. TDLib's own API - confirmed
// present in this wrapper version by reading TdlClient.kt - supports exactly
// the proxy-switching operations a real Telegram client uses to let a user
// change proxies without restarting: addProxy(proxy, enable, comment):
// TdlResult<AddedProxy> (AddedProxy.id identifies it), removeProxy(proxyId),
// enableProxy(proxyId), disableProxy(), getProxies(). So instead, a small
// FIXED POOL of SCAN_CONCURRENCY clients is created ONCE at the start of a
// scan and closed ONCE at the end (see runMassScan). Each pool worker below
// owns one persistent client for its whole lifetime and just cycles that one
// client's active proxy across its assigned candidates via
// removeProxy()/addProxy() - no client teardown happens between candidates,
// only at the very end of the run.
//
// connectionStateUpdates subtlety: TdlEngine.getUpdates() is backed by a hot,
// non-replaying MutableSharedFlow shared process-wide and filtered by client
// id (confirmed by reading TdlEngine.kt/TdlRepository.kt) - it is NOT a
// StateFlow, so it never hands a late subscriber a stale cached state. This
// worker still needs to guard against a *different* kind of staleness though:
// if it re-subscribed to connectionStateUpdates fresh for every candidate,
// a ConnectionStateReady left over from the *previous* candidate's proxy could
// still be sitting unconsumed and get misread as this candidate's. The fix
// here is to start exactly ONE persistent collector for the client's entire
// lifetime, forwarding every state transition into an unbounded Channel, and
// to drain (discard) whatever is already buffered in that channel immediately
// before each candidate's removeProxy()/addProxy() call. Everything received
// after that point is guaranteed to be a transition that happened at or after
// this candidate's proxy switch - a stale Ready can never leak into the wait.
private suspend fun runPoolWorker(
    filesDirPath: String,
    workerIndex: Int,
    assigned: List<IndexedValue<Candidate>>,
    totalSubset: Int,
    checked: java.util.concurrent.atomic.AtomicInteger,
    alive: java.util.concurrent.atomic.AtomicInteger,
    onStatus: (String) -> Unit,
    onProgress: (checked: Int, total: Int) -> Unit,
    onAlive: (AliveHit) -> Unit,
) = withContext(Dispatchers.Default) {
    if (assigned.isEmpty()) return@withContext
    coroutineScope {
        val dbDir = File(filesDirPath, "tdlib-pool-$workerIndex")
        val filesDirForClient = File(filesDirPath, "tdlib-pool-$workerIndex-files")
        val client = TdlClient.create()
        val closed = CompletableDeferred<Unit>()
        // Unbounded so the persistent collector below never suspends/drops an
        // event while this worker is off doing other suspend work (e.g.
        // inside an addProxy() round trip) between reads.
        val stateChannel = Channel<ConnectionState>(capacity = Channel.UNLIMITED)
        val stateCollectorJob = client.connectionStateUpdates
            .onEach { update -> stateChannel.trySend(update.state) }
            .launchIn(this)
        // Watched from client creation (not just after close() is requested) so
        // a client that somehow reaches Closed on its own (e.g. a TDLib-side
        // error path) is still observed correctly.
        val authCollectorJob = client.authorizationStateUpdates
            .onEach { update -> if (update.authorizationState is AuthorizationStateClosed) closed.complete(Unit) }
            .launchIn(this)

        try {
            val paramsResult = client.setTdlibParameters(
                useTestDc = false,
                databaseDirectory = dbDir.absolutePath,
                filesDirectory = filesDirForClient.absolutePath,
                databaseEncryptionKey = ByteArray(0),
                useFileDatabase = false,
                useChatInfoDatabase = false,
                useMessageDatabase = false,
                useSecretChats = false,
                apiId = BuildConfig.TG_API_ID,
                apiHash = BuildConfig.TG_API_HASH,
                systemLanguageCode = "ru",
                deviceModel = "TgProxyCheck-native-poc",
                systemVersion = "unknown",
                applicationVersion = "0.1",
            )
            if (paramsResult is TdlResult.Failure) {
                android.util.Log.e(
                    SCAN_TAG,
                    "pool worker #$workerIndex setTdlibParameters failed: " +
                        "${paramsResult.code} ${paramsResult.message} - " +
                        "${assigned.size} candidates on this worker are unreachable",
                )
                // The client never came up, so every candidate assigned to this
                // worker is unreachable - still advance `checked` for them so the
                // on-screen "Проверено N/M" counter reaches subset.size instead
                // of silently stalling short.
                assigned.forEach { _ ->
                    val checkedNow = checked.incrementAndGet()
                    onStatus("Проверено $checkedNow/$totalSubset, живых сейчас: ${alive.get()}")
                    onProgress(checkedNow, totalSubset)
                }
                return@coroutineScope
            }

            var lastProxyId: Int? = null
            for ((candidateIndex, candidate) in assigned) {
                val outcome = try {
                    checkOneCandidate(
                        client = client,
                        stateChannel = stateChannel,
                        previousProxyId = lastProxyId,
                        candidate = candidate,
                    )
                } catch (e: Throwable) {
                    android.util.Log.e(
                        SCAN_TAG,
                        "candidate #$candidateIndex (${candidate.server}:${candidate.port}) crashed the check " +
                            "on pool worker #$workerIndex: ${e::class.simpleName}: ${e.message}",
                        e,
                    )
                    // Unknown state after a genuine crash - safest assumption is
                    // "no proxy left active to clean up" rather than risk
                    // removeProxy()-ing an id that may not even be valid.
                    PoolCheckOutcome(result = null, proxyId = null)
                }
                lastProxyId = outcome.proxyId

                val checkedNow = checked.incrementAndGet()
                val result = outcome.result
                if (result != null) {
                    val aliveNow = alive.incrementAndGet()
                    onAlive(
                        AliveHit(
                            candidate = candidate,
                            pingMs = result.pingMs,
                            downloadKbps = result.downloadKbps,
                            uploadKbps = result.uploadKbps,
                        )
                    )
                    onStatus("Проверено $checkedNow/$totalSubset, живых сейчас: $aliveNow")
                } else {
                    onStatus("Проверено $checkedNow/$totalSubset, живых сейчас: ${alive.get()}")
                }
                onProgress(checkedNow, totalSubset)
            }
        } finally {
            try {
                stateCollectorJob.cancel()
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "pool worker #$workerIndex stateCollectorJob.cancel failed: ${e.message}", e)
            }
            // Same fix v0.7.2 shipped, now paid for once per pool worker instead
            // of once per candidate: close() only *requests* shutdown (its own
            // doc comment: "After the close completes, updateAuthorizationState
            // with authorizationStateClosed will be sent" - the suspend function
            // returning only means TDLib *received* the request). Wait for that
            // confirmation, bounded, before deleting this worker's db files.
            try {
                client.close()
                val confirmedClosed = withTimeoutOrNull(CLOSE_TIMEOUT_MS) { closed.await() } != null
                if (!confirmedClosed) {
                    android.util.Log.e(
                        SCAN_TAG,
                        "pool worker #$workerIndex client.close did not confirm AuthorizationStateClosed " +
                            "within ${CLOSE_TIMEOUT_MS}ms - possible native leak",
                    )
                }
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "pool worker #$workerIndex client.close failed: ${e.message}", e)
            }
            try {
                authCollectorJob.cancel()
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "pool worker #$workerIndex authCollectorJob.cancel failed: ${e.message}", e)
            }
            try {
                dbDir.deleteRecursively()
                filesDirForClient.deleteRecursively()
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "pool worker #$workerIndex cleanup of scan dirs failed: ${e.message}", e)
            }
        }
    }
}

// Runs on the pool worker's one persistent client - removes the previous
// candidate's proxy (if any), adds this candidate's, and waits for
// ConnectionStateReady via the worker's persistent state channel (see the
// staleness note on runPoolWorker for why this is safe against a leftover
// Ready from the previous candidate).
private suspend fun checkOneCandidate(
    client: TdlClient,
    stateChannel: Channel<ConnectionState>,
    previousProxyId: Int?,
    candidate: Candidate,
): PoolCheckOutcome {
    if (previousProxyId != null) {
        try {
            client.removeProxy(proxyId = previousProxyId)
        } catch (e: Throwable) {
            android.util.Log.e(SCAN_TAG, "removeProxy($previousProxyId) failed: ${e.message}", e)
        }
    }

    // Discard anything already buffered - a lingering Ready from the previous
    // candidate, transitions kicked off by the removeProxy() above, etc. - so
    // the wait below can only be satisfied by a transition that happens at or
    // after this point.
    while (stateChannel.tryReceive().isSuccess) {
        // drain
    }

    val proxyType: ProxyType = ProxyTypeMtproto(secret = candidate.secret)
    val proxy = Proxy(server = candidate.server, port = candidate.port, type = proxyType)
    val addResult = client.addProxy(proxy = proxy, enable = true, comment = "mass-scan")
    if (addResult is TdlResult.Failure) return PoolCheckOutcome(result = null, proxyId = null)
    val newProxyId = (addResult as TdlResult.Success).result.id

    val start = android.os.SystemClock.elapsedRealtime()
    val reached = withTimeoutOrNull(PER_PROXY_TIMEOUT_MS) {
        while (true) {
            val state = stateChannel.receive()
            if (state is ConnectionStateReady) break
        }
    } != null
    if (!reached) return PoolCheckOutcome(result = null, proxyId = newProxyId)
    val pingMs = android.os.SystemClock.elapsedRealtime() - start

    // Speed metric removed here (see AliveHit doc comment): TDLib's
    // NetworkStatistics never records pre-auth handshake bytes, so it
    // always came back 0.0/0.0 and was worse than showing nothing.
    return PoolCheckOutcome(
        result = ConnectResult(pingMs = pingMs, downloadKbps = null, uploadKbps = null),
        proxyId = newProxyId,
    )
}

private suspend fun fetchJsonCandidates(url: String, jsonArrayKey: String): List<Candidate> =
    withContext(Dispatchers.IO) {
        val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAll, SecureRandom())

        val connection = java.net.URL(url).openConnection() as HttpsURLConnection
        connection.sslSocketFactory = sslContext.socketFactory
        connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000

        val body = connection.inputStream.bufferedReader().use { it.readText() }
        val root = org.json.JSONObject(body)
        val itemsJson: JSONArray = if (root.has(jsonArrayKey)) root.getJSONArray(jsonArrayKey) else JSONArray(body)

        (0 until itemsJson.length()).map { i ->
            val o = itemsJson.getJSONObject(i)
            val secret = o.getString("secret")
            val domain = decodeFakeTlsDomain(secret)
            Candidate(
                server = o.getString("server"),
                port = o.getInt("port"),
                secret = secret,
                mtprotoMs = o.optInt("mtproto_ms", Int.MAX_VALUE),
                isProtectedDomain = isProtectedDomain(domain),
                category = classifyDomain(domain),
            )
        }
    }
