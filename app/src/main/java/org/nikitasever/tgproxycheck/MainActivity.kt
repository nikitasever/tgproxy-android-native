package org.nikitasever.tgproxycheck

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
import dev.g000sha256.tdl.dto.Proxy
import dev.g000sha256.tdl.dto.ProxyTypeMtproto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

// Known-good proxy from our own scraped pool (SoliSpirit source), independently
// confirmed reachable on this exact network via Telegram's own client without a VPN.
// This is the reference case the Python/Telethon build failed to validate against.
private const val TEST_SERVER = "go.pelmeshka.top"
private const val TEST_PORT = 443
private const val TEST_SECRET = "eeaa6a6fdb00cbaf8a0c257e6736ece98f676f2e70656c6d6573686b612e746f70"

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
            scope.launch { status = checkProxy(filesDirPath) }
        }) {
            Text("Проверить $TEST_SERVER:$TEST_PORT")
        }
    }
}

private suspend fun checkProxy(filesDirPath: String): String {
    val client = TdlClient.create()
    return try {
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
            return "FAIL: setTdlibParameters — [${paramsResult.code}] ${paramsResult.message}"
        }

        val proxy = Proxy(
            server = TEST_SERVER,
            port = TEST_PORT,
            type = ProxyTypeMtproto(secret = TEST_SECRET),
        )

        val pingResult = client.pingProxy(proxy)
        when (pingResult) {
            is TdlResult.Success -> "OK: пинг через прокси = ${pingResult.result.seconds} c"
            is TdlResult.Failure -> "FAIL: pingProxy — [${pingResult.code}] ${pingResult.message}"
        }
    } catch (e: Exception) {
        "FAIL: ${e::class.simpleName}: ${e.message}"
    } finally {
        client.close()
    }
}
