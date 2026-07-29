package org.nikitasever.tgproxycheck.nativeapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.g000sha256.tdl.TdlClient
import dev.g000sha256.tdl.TdlResult
import dev.g000sha256.tdl.dto.ConnectionStateConnecting
import dev.g000sha256.tdl.dto.ConnectionStateConnectingToProxy
import dev.g000sha256.tdl.dto.ConnectionStateReady
import dev.g000sha256.tdl.dto.ConnectionStateUpdating
import dev.g000sha256.tdl.dto.ConnectionStateWaitingForNetwork
import dev.g000sha256.tdl.dto.Proxy
import dev.g000sha256.tdl.dto.ProxyTypeMtproto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

// Freshest fastest proxy from a scan run moments before this build, MTProto-verified
// server-side by our own Telethon-based checker (mtproto_ms=3037, latency_ms=30).
// The previous go.pelmeshka.top test proxy had simply died by the time it was retested —
// confirmed independently via https://t.me/proxy?...go.pelmeshka.top — so this swaps in
// a proxy that's known-alive right now instead of one from a stale snapshot.
private const val TEST_SERVER = "87.58.201.74"
private const val TEST_PORT = 853
private const val TEST_SECRET = "ee6aa9eb2bd47d97b43be8ac203cfd3c0e7777772e676f6f676c652e636f6d"

// pingProxy is a single-shot probe with no retry — a real client (TDLib's own
// connection manager, used when the proxy is actually enabled) reconnects with
// backoff instead of failing on one dropped attempt. This gives that a chance to work.
private const val CHECK_TIMEOUT_MS = 30_000L

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
    var status by remember { mutableStateOf("Готово к проверке") }
    val scope = remember { CoroutineScope(Dispatchers.Main) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(text = status)
        Button(onClick = {
            status = "Проверяю через TDLib..."
            scope.launch { status = checkProxy(filesDirPath) { state -> status = state } }
        }) {
            Text("Проверить $TEST_SERVER:$TEST_PORT")
        }
    }
}

private suspend fun checkProxy(filesDirPath: String, onState: (String) -> Unit): String = coroutineScope {
    val client = TdlClient.create()
    val ready = CompletableDeferred<Unit>()

    // Must start collecting before the first request per the library's own README note.
    // This job never completes on its own — it must be cancelled explicitly, or the
    // enclosing coroutineScope would hang forever waiting for it to finish.
    val collectorJob = client.connectionStateUpdates
        .onEach { update ->
            val label = when (update.state) {
                is ConnectionStateWaitingForNetwork -> "Ожидание сети..."
                is ConnectionStateConnectingToProxy -> "Подключаюсь к прокси..."
                is ConnectionStateConnecting -> "Подключаюсь к Telegram..."
                is ConnectionStateUpdating -> "Синхронизация..."
                is ConnectionStateReady -> "Соединение установлено"
                else -> "..."
            }
            onState(label)
            if (update.state is ConnectionStateReady) ready.complete(Unit)
        }
        .launchIn(this)

    try {
        val paramsResult = client.setTdlibParameters(
            useTestDc = false,
            databaseDirectory = "$filesDirPath/tdlib",
            filesDirectory = "$filesDirPath/tdlib-files",
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
            return@coroutineScope "FAIL: setTdlibParameters — [${paramsResult.code}] ${paramsResult.message}"
        }

        val proxy = Proxy(
            server = TEST_SERVER,
            port = TEST_PORT,
            type = ProxyTypeMtproto(secret = TEST_SECRET),
        )

        val addResult = client.addProxy(proxy = proxy, enable = true, comment = "native-poc-test")
        if (addResult is TdlResult.Failure) {
            return@coroutineScope "FAIL: addProxy — [${addResult.code}] ${addResult.message}"
        }

        val succeeded = withTimeoutOrNull(CHECK_TIMEOUT_MS) { ready.await() } != null
        if (succeeded) {
            "OK: соединение через прокси установлено (ConnectionStateReady) — реальная сессия, не разовый пинг"
        } else {
            "FAIL: за ${CHECK_TIMEOUT_MS / 1000}с TDLib с ретраями так и не дошёл до готовности"
        }
    } catch (e: Exception) {
        "FAIL: ${e::class.simpleName}: ${e.message}"
    } finally {
        collectorJob.cancel()
        client.close()
    }
}
