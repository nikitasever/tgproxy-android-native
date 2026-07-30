package org.nikitasever.tgproxycheck.nativeapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
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

// The server's own results.json endpoint (self-signed cert, same trust-all
// approach the Python checker already uses server-side for its own requests).
private const val RESULTS_URL =
    "https://77.110.98.222:8765/results.json?token=M2Pxr2BUvkbrS-9CSu40D2CFwwgY0rxY"

// Scan only the fastest-verified subset — enough to see a real alive-rate signal
// without an excessively long single test run.
private const val SCAN_LIMIT = 60
private const val SCAN_CONCURRENCY = 6
private const val PER_PROXY_TIMEOUT_MS = 12_000L

data class Candidate(val server: String, val port: Int, val secret: String, val mtprotoMs: Int)

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
    val aliveResults = remember { mutableStateListOf<String>() }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
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
            Text("Массовое сканирование (топ $SCAN_LIMIT)")
        }

        Divider(modifier = Modifier.padding(vertical = 12.dp))

        LazyColumn {
            items(aliveResults) { line ->
                Text(text = line, modifier = Modifier.padding(vertical = 4.dp))
            }
        }
    }
}

private suspend fun runMassScan(
    filesDirPath: String,
    onStatus: (String) -> Unit,
    onAlive: (String) -> Unit,
) {
    val candidates = try {
        fetchCandidates()
    } catch (e: Exception) {
        onStatus("FAIL: не удалось получить список — ${e::class.simpleName}: ${e.message}")
        return
    }

    val subset = candidates.sortedBy { it.mtprotoMs }.take(SCAN_LIMIT)
    onStatus("Кандидатов: ${candidates.size}, проверяю топ ${subset.size}...")

    var checked = 0
    var alive = 0
    val semaphore = Semaphore(SCAN_CONCURRENCY)

    coroutineScope {
        subset.mapIndexed { index, candidate ->
            async {
                semaphore.acquire()
                try {
                    val ok = checkViaConnection(filesDirPath, index, candidate)
                    checked++
                    if (ok) {
                        alive++
                        onAlive("✓ ${candidate.server}:${candidate.port} (server mtproto=${candidate.mtprotoMs}мс)")
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
): Boolean = withContext(Dispatchers.Default) {
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
            if (paramsResult is TdlResult.Failure) return@coroutineScope false

            val proxyType: ProxyType = ProxyTypeMtproto(secret = candidate.secret)
            val proxy = Proxy(server = candidate.server, port = candidate.port, type = proxyType)
            val addResult = client.addProxy(proxy = proxy, enable = true, comment = "mass-scan")
            if (addResult is TdlResult.Failure) return@coroutineScope false

            withTimeoutOrNull(PER_PROXY_TIMEOUT_MS) { ready.await() } != null
        } catch (e: Exception) {
            false
        } finally {
            collectorJob.cancel()
            client.close()
        }
    }
}

private suspend fun fetchCandidates(): List<Candidate> = withContext(Dispatchers.IO) {
    val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustAll, SecureRandom())

    val url = java.net.URL(RESULTS_URL)
    val connection = url.openConnection() as HttpsURLConnection
    connection.sslSocketFactory = sslContext.socketFactory
    connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
    connection.connectTimeout = 15_000
    connection.readTimeout = 15_000

    val body = connection.inputStream.bufferedReader().use { it.readText() }
    val root = org.json.JSONObject(body)
    val proxiesJson: JSONArray = if (root.has("proxies")) root.getJSONArray("proxies") else JSONArray(body)

    (0 until proxiesJson.length()).map { i ->
        val o = proxiesJson.getJSONObject(i)
        Candidate(
            server = o.getString("server"),
            port = o.getInt("port"),
            secret = o.getString("secret"),
            mtprotoMs = o.optInt("mtproto_ms", 999_999),
        )
    }
}
