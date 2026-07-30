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

// The server verifies from its own VPS/datacenter IP, which some MTProxy operators
// block outright (a common anti-scanning measure) — confirmed by hand: proxies the
// phone connects to fine sometimes fail the server's own from-VPS check. So its
// "verified" list under-counts what actually works for a real device and can't be
// trusted as the pool to draw from; the raw, unfiltered candidates.json pool (tested
// live from this phone) is the only reliable ground truth.
private const val REGULAR_FILL_LIMIT = 350
private const val SCAN_CONCURRENCY = 16
private const val PER_PROXY_TIMEOUT_MS = 6_000L

data class Candidate(
    val server: String,
    val port: Int,
    val secret: String,
    val mtprotoMs: Int,
    val isProtectedDomain: Boolean,
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

data class AliveHit(val candidate: Candidate, val pingMs: Long)

private const val GITHUB_LATEST_RELEASE_URL =
    "https://api.github.com/repos/nikitasever/tgproxy-android-native/releases/latest"

data class UpdateInfo(val version: String, val downloadUrl: String)

private suspend fun checkForUpdate(): UpdateInfo? = withContext(Dispatchers.IO) {
    try {
        val connection = java.net.URL(GITHUB_LATEST_RELEASE_URL).openConnection() as HttpsURLConnection
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        val body = connection.inputStream.bufferedReader().use { it.readText() }
        val root = org.json.JSONObject(body)
        val tagName = root.getString("tag_name").removePrefix("v")
        if (tagName == BuildConfig.VERSION_NAME) return@withContext null

        val assets = root.getJSONArray("assets")
        var downloadUrl: String? = null
        for (i in 0 until assets.length()) {
            val asset = assets.getJSONObject(i)
            if (asset.getString("name") == "app-debug.apk") {
                downloadUrl = asset.getString("browser_download_url")
                break
            }
        }
        downloadUrl?.let { UpdateInfo(version = tagName, downloadUrl = it) }
    } catch (e: Exception) {
        null
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

@Composable
fun ProxyCheckScreen(filesDirPath: String) {
    var status by remember { mutableStateOf("Готово") }
    val scope = remember { CoroutineScope(Dispatchers.Main) }
    val aliveResults = remember { mutableStateListOf<AliveHit>() }
    val context = LocalContext.current

    var updateInfo by remember { mutableStateOf<UpdateInfo?>(null) }
    var updateStatus by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        updateInfo = checkForUpdate()
    }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
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

        Button(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            onClick = {
                aliveResults.clear()
                status = "Загружаю список кандидатов..."
                scope.launch {
                    runMassScan(filesDirPath, onStatus = { status = it }, onAlive = { aliveResults.add(it) })
                }
            },
        ) {
            Text("Массовое сканирование")
        }

        Divider(modifier = Modifier.padding(vertical = 12.dp))

        LazyColumn {
            items(aliveResults) { hit ->
                val tag = if (hit.candidate.isProtectedDomain) " [защищённый домен]" else ""
                Text(
                    text = "✓ ${hit.candidate.server}:${hit.candidate.port}$tag — ${hit.pingMs}мс — добавить в Telegram",
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

private suspend fun runMassScan(
    filesDirPath: String,
    onStatus: (String) -> Unit,
    onAlive: (AliveHit) -> Unit,
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

    var checked = 0
    var alive = 0
    val semaphore = Semaphore(SCAN_CONCURRENCY)

    coroutineScope {
        subset.mapIndexed { index, candidate ->
            async {
                semaphore.acquire()
                try {
                    val pingMs = checkViaConnection(filesDirPath, index, candidate)
                    checked++
                    if (pingMs != null) {
                        alive++
                        onAlive(AliveHit(candidate, pingMs))
                    }
                    onStatus("Проверено $checked/${subset.size}, живых сейчас: $alive")
                } finally {
                    semaphore.release()
                }
            }
        }.awaitAll()
    }

    onStatus("Готово: $alive из ${subset.size} живы прямо сейчас (сервер верифицировал все ${subset.size} ранее)")
}

private suspend fun checkViaConnection(
    filesDirPath: String,
    index: Int,
    candidate: Candidate,
): Long? = withContext(Dispatchers.Default) {
    coroutineScope {
        val client = TdlClient.create()
        val ready = CompletableDeferred<Unit>()
        val collectorJob = client.connectionStateUpdates
            .onEach { update -> if (update.state is ConnectionStateReady) ready.complete(Unit) }
            .launchIn(this)
        try {
            val paramsResult = client.setTdlibParameters(
                useTestDc = false,
                databaseDirectory = "$filesDirPath/tdlib-scan-$index",
                filesDirectory = "$filesDirPath/tdlib-scan-$index-files",
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
            val addResult = client.addProxy(proxy = proxy, enable = true, comment = "mass-scan")
            if (addResult is TdlResult.Failure) return@coroutineScope null

            val start = android.os.SystemClock.elapsedRealtime()
            val reached = withTimeoutOrNull(PER_PROXY_TIMEOUT_MS) { ready.await() } != null
            if (reached) android.os.SystemClock.elapsedRealtime() - start else null
        } catch (e: Exception) {
            null
        } finally {
            collectorJob.cancel()
            client.close()
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
            Candidate(
                server = o.getString("server"),
                port = o.getInt("port"),
                secret = secret,
                mtprotoMs = o.optInt("mtproto_ms", Int.MAX_VALUE),
                isProtectedDomain = isProtectedDomain(decodeFakeTlsDomain(secret)),
            )
        }
    }
