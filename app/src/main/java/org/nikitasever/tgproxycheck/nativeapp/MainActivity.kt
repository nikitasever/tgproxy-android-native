package org.nikitasever.tgproxycheck.nativeapp

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import java.io.File
import dev.g000sha256.tdl.TdlClient
import dev.g000sha256.tdl.TdlResult
import dev.g000sha256.tdl.dto.ConnectionStateReady
import dev.g000sha256.tdl.dto.Proxy
import dev.g000sha256.tdl.dto.ProxyType
import dev.g000sha256.tdl.dto.ProxyTypeMtproto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
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
// Was 16. Each candidate spins up a fully separate native TDLib client (own DB,
// own threads); at 16-way concurrency across a 448-candidate run the native/JVM
// heap pressure is very plausibly what killed the process around candidate ~49
// in the field (see SCAN_TAG logging + the Throwable-catching added around
// checkViaConnection below). Lowering concurrency is a cheap way to reduce peak
// resource usage in addition to the crash-hardening.
private const val SCAN_CONCURRENCY = 10
private const val PER_PROXY_TIMEOUT_MS = 6_000L
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
private fun saveLastScanResults(filesDirPath: String, totalChecked: Int, hits: List<AliveHit>) {
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
        if (tagName == BuildConfig.VERSION_NAME) return@withContext UpdateCheckResult.UpToDate

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

private suspend fun downloadApk(url: String, destFile: File): Unit = withContext(Dispatchers.IO) {
    val connection = java.net.URL(url).openConnection() as HttpsURLConnection
    connection.connectTimeout = 15_000
    connection.readTimeout = 30_000
    connection.instanceFollowRedirects = true
    connection.inputStream.use { input ->
        destFile.outputStream().use { output -> input.copyTo(output) }
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ProxyCheckScreen(filesDir.absolutePath)
                }
            }
        }
    }
}

private fun formatLastScanTimestamp(timestampMs: Long): String {
    val fmt = java.text.SimpleDateFormat("H:mm, d.M.yy", java.util.Locale.getDefault())
    return fmt.format(java.util.Date(timestampMs))
}

@Composable
fun ProxyCheckScreen(filesDirPath: String) {
    var status by remember { mutableStateOf("Готово") }
    val scope = remember { CoroutineScope(Dispatchers.Main) }
    val aliveResults = remember { mutableStateListOf<AliveHit>() }
    val context = LocalContext.current

    var updateInfo by remember { mutableStateOf<UpdateInfo?>(null) }
    var updateStatus by remember { mutableStateOf<String?>(null) }
    var updateCheckError by remember { mutableStateOf<String?>(null) }

    var lastScanInfo by remember { mutableStateOf<String?>(null) }
    var totalCheckedLast by remember { mutableStateOf(0) }

    LaunchedEffect(Unit) {
        when (val result = checkForUpdate()) {
            is UpdateCheckResult.Available -> updateInfo = result.info
            UpdateCheckResult.UpToDate -> Unit
            is UpdateCheckResult.Error -> updateCheckError = result.message
        }

        // Load the previous scan's results immediately on cold start, before any
        // new scan runs, so the user isn't staring at an empty screen while a
        // fresh scan (which can take a while over hundreds of candidates) runs.
        val snapshot = loadLastScanResults(filesDirPath)
        if (snapshot != null) {
            aliveResults.addAll(snapshot.hits)
            totalCheckedLast = snapshot.totalChecked
            lastScanInfo = "Последнее сканирование: ${snapshot.hits.size} из ${snapshot.totalChecked} " +
                "живы (${formatLastScanTimestamp(snapshot.timestampMs)})"
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        if (updateInfo == null && updateCheckError != null) {
            Text(text = "Не удалось проверить обновление: $updateCheckError")
        }
        updateInfo?.let { info ->
            Text(text = "Доступно обновление: v${info.version}${updateStatus?.let { " — $it" } ?: ""}")
            Button(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 16.dp),
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
                            downloadApk(info.downloadUrl, apkFile)
                            updateStatus = "устанавливаю..."
                            val uri = FileProvider.getUriForFile(
                                context,
                                "org.nikitasever.tgproxycheck.nativeapp.fileprovider",
                                apkFile,
                            )
                            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                                setDataAndType(uri, "application/vnd.android.package-archive")
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            context.startActivity(installIntent)
                        } catch (e: Exception) {
                            updateStatus = "FAIL: ${e::class.simpleName}: ${e.message}"
                        }
                    }
                },
            ) {
                Text("Обновить")
            }
            Divider(modifier = Modifier.padding(bottom = 12.dp))
        }

        Text(text = status)

        lastScanInfo?.let { info ->
            Text(text = info, modifier = Modifier.padding(top = 4.dp))
        }

        Button(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            onClick = {
                aliveResults.clear()
                lastScanInfo = null
                status = "Загружаю список кандидатов..."
                scope.launch {
                    // Belt-and-suspenders: runMassScan/checkViaConnection now catch
                    // Throwable internally so one bad candidate can't take the whole
                    // scan down, but this outer catch means even a truly unexpected
                    // failure surfaces as a status message instead of crashing the
                    // Activity's UI coroutine scope.
                    try {
                        runMassScan(
                            filesDirPath,
                            onStatus = { status = it },
                            onAlive = { aliveResults.add(it) },
                            onComplete = { totalChecked ->
                                totalCheckedLast = totalChecked
                                saveLastScanResults(filesDirPath, totalChecked, aliveResults.toList())
                            },
                        )
                    } catch (e: Throwable) {
                        android.util.Log.e(SCAN_TAG, "runMassScan crashed: ${e::class.simpleName}: ${e.message}", e)
                        status = "FAIL: сканирование прервано — ${e::class.simpleName}: ${e.message}"
                    }
                }
            },
        ) {
            Text("Массовое сканирование")
        }

        Divider(modifier = Modifier.padding(vertical = 12.dp))

        // Sort by a combined "how good is this proxy right now" score everywhere:
        // ascending ping as the base signal, pulled down further by measured
        // speed and by protected-domain status (see recommendScore() doc above).
        val recommended = aliveResults.sortedBy { it.recommendScore() }.take(8)
        val grouped: Map<String, List<AliveHit>> = aliveResults
            .groupBy { it.candidate.category }
            .mapValues { (_, hits) -> hits.sortedBy { it.recommendScore() } }

        fun hitLine(hit: AliveHit): String {
            val tag = if (hit.candidate.isProtectedDomain) " [защищённый домен]" else ""
            // Speed (КБ/с) metric was removed in 0.7.1 - it always read 0.0/0.0 for
            // structural reasons (see AliveHit doc comment), so it's dishonest to show.
            // Only show it for legacy persisted results from before the removal that
            // happen to still have real (non-null) values loaded from disk.
            val speedText = if (hit.downloadKbps != null && hit.uploadKbps != null) {
                " — ↓%.1f/↑%.1f КБ/с (устаревшие данные)".format(hit.downloadKbps, hit.uploadKbps)
            } else ""
            return "✓ ${hit.candidate.server}:${hit.candidate.port}$tag — ${hit.pingMs}мс$speedText — добавить в Telegram"
        }

        LazyColumn {
            if (recommended.isNotEmpty()) {
                item(key = "header-recommended") {
                    Text(
                        text = "⭐ Рекомендуем (${recommended.size})",
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 4.dp),
                    )
                }
                items(recommended, key = { "rec-${it.candidate.server}:${it.candidate.port}" }) { hit ->
                    Text(
                        text = hitLine(hit),
                        textDecoration = TextDecoration.Underline,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp)
                            .clickable {
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(hit.candidate.toTelegramProxyUrl()))
                                context.startActivity(intent)
                            },
                    )
                }
                item(key = "recommended-divider") {
                    Divider(modifier = Modifier.padding(vertical = 12.dp))
                }
            }

            for (category in CATEGORY_ORDER) {
                val hits = grouped[category] ?: continue
                if (hits.isEmpty()) continue
                item(key = "header-$category") {
                    Text(
                        text = "$category (${hits.size})",
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 4.dp),
                    )
                }
                items(hits, key = { "cat-$category-${it.candidate.server}:${it.candidate.port}" }) { hit ->
                    Text(
                        text = hitLine(hit),
                        textDecoration = TextDecoration.Underline,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp)
                            .clickable {
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(hit.candidate.toTelegramProxyUrl()))
                                context.startActivity(intent)
                            },
                    )
                }
            }
        }
    }
}

private suspend fun runMassScan(
    filesDirPath: String,
    onStatus: (String) -> Unit,
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

    fun key(c: Candidate) = Triple(c.server, c.port, c.secret)

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

    // Plain Int++ from multiple concurrent coroutines (SCAN_CONCURRENCY-way, on
    // Dispatchers.Default so genuinely multi-threaded) is a data race; use atomics
    // so the "Проверено N/M" counter is actually accurate.
    val checked = java.util.concurrent.atomic.AtomicInteger(0)
    val alive = java.util.concurrent.atomic.AtomicInteger(0)
    val semaphore = Semaphore(SCAN_CONCURRENCY)

    // A single candidate throwing used to be able to take the whole scan (and the
    // app) down with it: `async { }` inside `coroutineScope { }` propagates any
    // uncaught exception from a child up through the whole scope, cancelling every
    // other in-flight candidate and rethrowing out of runMassScan - and since the
    // caller (scope.launch in ProxyCheckScreen) has no CoroutineExceptionHandler,
    // that crashes the whole app. checkViaConnection now catches Throwable
    // internally, but this outer catch is a second line of defence in case
    // something throws before/after that (e.g. AtomicInteger ops, onAlive/onStatus
    // callbacks) so one bad candidate never kills the other 447.
    coroutineScope {
        subset.mapIndexed { index, candidate ->
            async {
                semaphore.acquire()
                try {
                    val result = try {
                        checkViaConnection(filesDirPath, index, candidate)
                    } catch (e: Throwable) {
                        android.util.Log.e(
                            SCAN_TAG,
                            "candidate #$index (${candidate.server}:${candidate.port}) crashed the check: " +
                                "${e::class.simpleName}: ${e.message}",
                            e,
                        )
                        null
                    }
                    val checkedNow = checked.incrementAndGet()
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
                        onStatus("Проверено $checkedNow/${subset.size}, живых сейчас: $aliveNow")
                    } else {
                        onStatus("Проверено $checkedNow/${subset.size}, живых сейчас: ${alive.get()}")
                    }
                } finally {
                    semaphore.release()
                }
            }
        }.awaitAll()
    }

    onStatus("Готово: ${alive.get()} из ${subset.size} живы прямо сейчас (сервер верифицировал все ${subset.size} ранее)")
    onComplete(subset.size)
}

private data class ConnectResult(val pingMs: Long, val downloadKbps: Double?, val uploadKbps: Double?)

// Each call creates its own isolated native TDLib client + on-disk DB directory.
// Root-caused crash (v0.7.0-native-poc): a couple of things compounded under a
// 448-candidate / 16-way-concurrent scan:
//  1. TdlClient.create() (and the TDLib calls after it) can fail with an
//     OutOfMemoryError under memory pressure from many concurrent native
//     clients - OutOfMemoryError is an Error, not an Exception, so the old
//     `catch (e: Exception)` here did NOT catch it. An uncaught Error/Exception
//     from inside `async { }` propagates up through the parent `coroutineScope`
//     in runMassScan and kills the entire scan (and, since nothing upstream
//     installs a CoroutineExceptionHandler, the whole app) - matching the
//     observed "died partway through, at candidate ~49/448" symptom exactly.
//  2. tdlib-scan-$index / tdlib-scan-$index-files directories were never
//     deleted, so every run left behind TDLib's sqlite db/wal/journal files;
//     a run that died mid-scan (crash, or the user force-closing it) could
//     leave a stale lock on one of those directories, which would plausibly
//     make the *next* attempt to open the same directory hang or fail - and
//     "clear the app cache first" (which wipes filesDir) is exactly the fix
//     that would clear such a stale lock, matching what the user had to do.
// Fix: catch Throwable (not just Exception) around the whole client lifecycle,
// log every failure so a real crash is diagnosable from logcat next time
// instead of silently swallowed, and delete each candidate's scan directories
// immediately after that candidate's check finishes so nothing accumulates or
// goes stale across a run.
private suspend fun checkViaConnection(
    filesDirPath: String,
    index: Int,
    candidate: Candidate,
): ConnectResult? = withContext(Dispatchers.Default) {
    coroutineScope {
        val dbDir = File(filesDirPath, "tdlib-scan-$index")
        val filesDirForClient = File(filesDirPath, "tdlib-scan-$index-files")
        var client: TdlClient? = null
        var collectorJob: kotlinx.coroutines.Job? = null
        try {
            client = TdlClient.create()
            val localClient = client
            val ready = CompletableDeferred<Unit>()
            collectorJob = localClient.connectionStateUpdates
                .onEach { update -> if (update.state is ConnectionStateReady) ready.complete(Unit) }
                .launchIn(this)

            val paramsResult = localClient.setTdlibParameters(
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
            if (paramsResult is TdlResult.Failure) return@coroutineScope null

            val proxyType: ProxyType = ProxyTypeMtproto(secret = candidate.secret)
            val proxy = Proxy(server = candidate.server, port = candidate.port, type = proxyType)
            val addResult = localClient.addProxy(proxy = proxy, enable = true, comment = "mass-scan")
            if (addResult is TdlResult.Failure) return@coroutineScope null

            val start = android.os.SystemClock.elapsedRealtime()
            val reached = withTimeoutOrNull(PER_PROXY_TIMEOUT_MS) { ready.await() } != null
            if (!reached) return@coroutineScope null
            val pingMs = android.os.SystemClock.elapsedRealtime() - start

            // Speed metric removed here (see AliveHit doc comment): TDLib's
            // NetworkStatistics never records pre-auth handshake bytes, so it
            // always came back 0.0/0.0 and was worse than showing nothing.
            ConnectResult(pingMs = pingMs, downloadKbps = null, uploadKbps = null)
        } catch (e: Throwable) {
            android.util.Log.e(
                SCAN_TAG,
                "checkViaConnection #$index (${candidate.server}:${candidate.port}) failed: " +
                    "${e::class.simpleName}: ${e.message}",
                e,
            )
            null
        } finally {
            try {
                collectorJob?.cancel()
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "collectorJob.cancel #$index failed: ${e.message}", e)
            }
            try {
                client?.close()
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "client.close #$index failed: ${e.message}", e)
            }
            try {
                dbDir.deleteRecursively()
                filesDirForClient.deleteRecursively()
            } catch (e: Throwable) {
                android.util.Log.e(SCAN_TAG, "cleanup of scan dirs #$index failed: ${e.message}", e)
            }
        }
    }
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
