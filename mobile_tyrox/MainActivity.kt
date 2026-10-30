package com.tyrox.mobile

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.ViewGroup
import android.widget.*
import android.widget.FrameLayout
import org.webrtc.*
import org.webrtc.PeerConnection.IceConnectionState
import org.webrtc.PeerConnection.IceGatheringState
import org.webrtc.PeerConnection.SignalingState
import org.json.JSONObject
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.*

class MainActivity : Activity() {
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var token: EditText
    private lateinit var fingerprint: EditText
    private lateinit var remotePath: EditText
    private lateinit var status: TextView
    private lateinit var files: ListView
    private val entries = mutableListOf<RemoteEntry>()
    private var client: OkHttpClient? = null
    private var baseUrl = ""
    private val pickUpload = 101
    private val pickSave = 102
    private var downloadEntry: RemoteEntry? = null
    private var screenEnabled = false
    private var eglBase: EglBase? = null
    private var peerFactory: PeerConnectionFactory? = null
    @Volatile private var viewerPeer: PeerConnection? = null
    @Volatile private var remoteVideoTrack: VideoTrack? = null
    private lateinit var videoRenderer: SurfaceViewRenderer
    private lateinit var viewButton: Button
    private lateinit var stopViewButton: Button

    data class RemoteEntry(val name: String, val isDirectory: Boolean, val size: Long)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = android.graphics.Color.rgb(12, 13, 18)
        window.navigationBarColor = android.graphics.Color.rgb(12, 13, 18)
        initializeWebRtc()
        buildUi()
    }

    private fun buildUi() {
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 30, 24, 24)
            setBackgroundColor(android.graphics.Color.rgb(12, 13, 18))
        }
        scroll.addView(root)
        setContentView(scroll)
        root.addView(TextView(this).apply {
            text = "TYROX MOBILE"
            textSize = 26f; setTextColor(-1); letterSpacing = .14f
        })
        root.addView(TextView(this).apply {
            text = "Secure local-network file transfer · Alpha 0.3"
            textSize = 13f; setTextColor(0xFF9CA3AF.toInt()); setPadding(0, 4, 0, 20)
        })
        host = field("Computer IP (e.g. 192.168.1.20)").also { root.addView(it) }
        port = field("Port", "47821").also { root.addView(it) }
        token = field("Pairing token").also { it.inputType = 129; root.addView(it) }
        fingerprint = field("SHA-256 certificate fingerprint (64 hex chars)").also { root.addView(it) }
        remotePath = field("Remote folder path", "").also { root.addView(it) }
        root.addView(button("Connect securely", true) { connect() })
        root.addView(button("Refresh file list") { refreshFiles() })
        root.addView(button("Send file to computer") { openUploadPicker() })
        root.addView(button("Save selected file to phone") { saveSelected() })
        viewButton = button("Request live screen view (owner approval required)", true) { requestLiveView() }
        viewButton.isEnabled = false
        root.addView(viewButton)
        stopViewButton = button("Stop live view") { stopLiveView("Live view stopped on this phone.") }
        stopViewButton.isEnabled = false
        root.addView(stopViewButton)
        videoRenderer = SurfaceViewRenderer(this)
        videoRenderer.setEnableHardwareScaler(true)
        videoRenderer.setMirror(false)
        videoRenderer.init(eglBase!!.eglBaseContext, null)
        videoRenderer.setBackgroundColor(android.graphics.Color.BLACK)
        root.addView(videoRenderer, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 560).apply { topMargin = 8 })
        status = TextView(this).apply {
            text = "Not connected. Enter the PC IP, pairing token, and certificate fingerprint."
            textSize = 14f; setTextColor(0xFFE5E7EB.toInt()); setPadding(0, 16, 0, 12)
        }
        root.addView(status)
        root.addView(TextView(this).apply { text = "REMOTE FILES"; textSize = 12f; letterSpacing = .1f; setTextColor(0xFF9CA3AF.toInt()) })
        files = ListView(this).apply {
            divider = android.graphics.drawable.ColorDrawable(0xFF272A33.toInt())
            dividerHeight = 1
            setBackgroundColor(0xFF171922.toInt())
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 480)
        }
        root.addView(files)
    }

    private fun field(hintText: String, initial: String = ""): EditText = EditText(this).apply {
        hint = hintText; setSingleLine(true); setText(initial)
        setTextColor(-1); setHintTextColor(0xFF8B91A1.toInt())
        setPadding(14, 8, 14, 8)
        background = android.graphics.drawable.GradientDrawable().apply {
            setColor(0xFF191C25.toInt()); cornerRadius = 18f; setStroke(1, 0xFF343846.toInt())
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = 10 }
    }

    private fun button(label: String, primary: Boolean = false, action: () -> Unit) = Button(this).apply {
        text = label; isAllCaps = false; setTextColor(-1)
        backgroundTintList = android.content.res.ColorStateList.valueOf(if (primary) 0xFF6D4AFF.toInt() else 0xFF252936.toInt())
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = 8 }
    }

    private fun makeClient(expectedFingerprint: String): OkHttpClient {
        val normalized = expectedFingerprint.replace(":", "").replace(" ", "").lowercase()
        require(normalized.matches(Regex("[0-9a-f]{64}"))) { "Fingerprint must be exactly 64 hexadecimal characters." }
        val trustManager = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String?) {
                if (chain.isEmpty()) throw java.security.cert.CertificateException("Server did not provide a certificate")
                val actual = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded).joinToString("") { "%02x".format(it) }
                if (!MessageDigest.isEqual(actual.toByteArray(), normalized.toByteArray())) {
                    throw java.security.cert.CertificateException("Certificate fingerprint mismatch. Connection rejected.")
                }
            }
        }
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trustManager), java.security.SecureRandom()) }
        return OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trustManager)
            // The user explicitly pins the exact certificate fingerprint above; local certificates may use IP SANs inconsistently.
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(8, TimeUnit.SECONDS).readTimeout(75, TimeUnit.SECONDS)
            .callTimeout(0, TimeUnit.MILLISECONDS).build()
    }

    private fun connect() {
        try {
            val h = host.text.toString().trim().removePrefix("https://").trimEnd('/')
            val p = port.text.toString().trim().toInt()
            require(h.isNotBlank() && p in 1..65535) { "Enter a valid computer IP and port." }
            val t = token.text.toString().trim()
            require(t.length >= 16) { "Pairing token looks too short." }
            val fp = fingerprint.text.toString().trim()
            val c = makeClient(fp)
            baseUrl = "https://$h:$p"
            client = c
            status.text = "Checking pinned TLS certificate and pairing token…"
            runAsync {
                val response = request("/api/health").get().build().let { c.newCall(it).execute() }
                val body = response.body?.string().orEmpty()
                if (!response.isSuccessful) error("Connection failed (${response.code}): $body")
                val json = JSONObject(body)
                screenEnabled = json.optBoolean("allowScreenRequests", false)
                runOnUiThread {
                    status.text = "Connected to ${json.optString("name", h)} · HTTPS certificate pinned"
                    viewButton.isEnabled = screenEnabled
                    if (!screenEnabled) status.text = "Connected · Screen viewing is disabled by the PC owner."
                    refreshFiles()
                }
            }
        } catch (e: Exception) { showError(e.message ?: "Invalid connection settings") }
    }

    private fun request(path: String): Request.Builder {
        val c = client ?: error("Connect first")
        val auth = token.text.toString().trim()
        return Request.Builder().url(baseUrl + path).header("Authorization", "Bearer $auth")
    }

    private fun refreshFiles() {
        if (client == null) { showError("Connect first"); return }
        val path = Uri.encode(remotePath.text.toString().trim(), "/")
        runAsync {
            val response = client!!.newCall(request("/api/files?path=$path").get().build()).execute()
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) error("Could not list files (${response.code}): $body")
            val json = JSONObject(body)
            val array = json.getJSONArray("entries")
            val result = mutableListOf<RemoteEntry>()
            for (i in 0 until array.length()) {
                val item = array.getJSONObject(i)
                result.add(RemoteEntry(item.getString("name"), item.optBoolean("isDirectory"), item.optLong("size")))
            }
            runOnUiThread {
                entries.clear(); entries.addAll(result)
                files.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_activated_1, entries.map { (if (it.isDirectory) "▸  " else "   ") + it.name + if (it.isDirectory) "/" else "  ·  ${formatSize(it.size)}" })
                files.choiceMode = ListView.CHOICE_MODE_SINGLE
                status.text = "Connected · ${entries.size} items listed"
            }
        }
    }

    private fun initializeWebRtc() {
        PeerConnectionFactory.initialize(PeerConnectionFactory.InitializationOptions.builder(this).createInitializationOptions())
        eglBase = EglBase.create()
        val encoder = DefaultVideoEncoderFactory(eglBase!!.eglBaseContext, true, true)
        val decoder = DefaultVideoDecoderFactory(eglBase!!.eglBaseContext)
        peerFactory = PeerConnectionFactory.builder().setVideoEncoderFactory(encoder).setVideoDecoderFactory(decoder).createPeerConnectionFactory()
    }

    private fun requestLiveView() {
        if (client == null) { showError("Connect to a PC first."); return }
        if (!screenEnabled) { showError("The PC owner has disabled screen-view requests."); return }
        if (viewerPeer != null) stopLiveView("Restarting live view…")
        viewButton.isEnabled = false
        status.text = "Creating encrypted WebRTC request. The PC owner must approve it…"
        runAsync {
            var pc: PeerConnection? = null
            try {
                pc = peerFactory!!.createPeerConnection(PeerConnection.RTCConfiguration(emptyList()), ViewerObserver())
                    ?: error("Could not create WebRTC peer connection")
                viewerPeer = pc
                pc.addTransceiver(MediaStreamTrack.MediaType.MEDIA_TYPE_VIDEO,
                    RtpTransceiver.RtpTransceiverInit(RtpTransceiver.RtpTransceiverDirection.RECV_ONLY))
                val offer = createOffer(pc)
                setDescription(pc, offer, true)
                val deadline = System.currentTimeMillis() + 12_000
                while (pc.iceGatheringState() != IceGatheringState.COMPLETE && System.currentTimeMillis() < deadline) Thread.sleep(100)
                val local = pc.localDescription ?: error("WebRTC offer was not created")
                val payload = JSONObject().put("offer", JSONObject().put("type", local.type.canonicalForm()).put("sdp", local.description)).put("requester", "TYROX Mobile")
                val body = payload.toString().toRequestBody("application/json; charset=utf-8".toMediaType())
                val response = client!!.newCall(request("/api/stream/offer").post(body).build()).execute()
                val responseText = response.body?.string().orEmpty()
                if (!response.isSuccessful) error("Screen request rejected (${response.code}): $responseText")
                val answerJson = JSONObject(responseText).getJSONObject("answer")
                setDescription(pc, SessionDescription(SessionDescription.Type.ANSWER, answerJson.getString("sdp")), false)
                runOnUiThread { status.text = "Screen-view request approved. Waiting for video…"; stopViewButton.isEnabled = true }
            } catch (e: Exception) {
                try { pc?.close() } catch (_: Exception) {}
                if (viewerPeer === pc) viewerPeer = null
                runOnUiThread { status.text = "Live view failed: ${e.message ?: "Unknown error"}"; viewButton.isEnabled = screenEnabled; stopViewButton.isEnabled = false }
            }
        }
    }

    private fun createOffer(pc: PeerConnection): SessionDescription {
        val latch = CountDownLatch(1); val result = AtomicReference<SessionDescription?>(); val failure = AtomicReference<String?>()
        pc.createOffer(object : SdpObserver {
            override fun onCreateSuccess(desc: SessionDescription) { result.set(desc); latch.countDown() }
            override fun onSetSuccess() {}
            override fun onCreateFailure(error: String) { failure.set(error); latch.countDown() }
            override fun onSetFailure(error: String) { failure.set(error); latch.countDown() }
        }, MediaConstraints())
        if (!latch.await(15, TimeUnit.SECONDS)) error("Timed out creating WebRTC offer")
        failure.get()?.let { error(it) }
        return result.get() ?: error("WebRTC did not return an offer")
    }

    private fun setDescription(pc: PeerConnection, desc: SessionDescription, local: Boolean) {
        val latch = CountDownLatch(1); val failure = AtomicReference<String?>()
        val observer = object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) {}
            override fun onSetSuccess() { latch.countDown() }
            override fun onCreateFailure(error: String) { failure.set(error); latch.countDown() }
            override fun onSetFailure(error: String) { failure.set(error); latch.countDown() }
        }
        if (local) pc.setLocalDescription(observer, desc) else pc.setRemoteDescription(observer, desc)
        if (!latch.await(15, TimeUnit.SECONDS)) error("Timed out setting WebRTC description")
        failure.get()?.let { error(it) }
    }

    private inner class ViewerObserver : PeerConnection.Observer {
        override fun onSignalingChange(state: SignalingState) {}
        override fun onIceConnectionChange(state: IceConnectionState) {
            runOnUiThread {
                if (state == IceConnectionState.CONNECTED || state == IceConnectionState.COMPLETED) status.text = "Live screen connected · View-only session"
                else if (state == IceConnectionState.FAILED || state == IceConnectionState.DISCONNECTED) status.text = "Screen connection interrupted: $state"
            }
        }
        override fun onIceConnectionReceivingChange(receiving: Boolean) {}
        override fun onIceGatheringChange(state: IceGatheringState) {}
        override fun onIceCandidate(candidate: IceCandidate) {}
        override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {}
        override fun onAddStream(stream: MediaStream) { stream.videoTracks.firstOrNull()?.let { attachVideo(it) } }
        override fun onRemoveStream(stream: MediaStream) { stream.videoTracks.forEach { it.removeSink(videoRenderer) } }
        override fun onDataChannel(channel: DataChannel) { channel.close() }
        override fun onRenegotiationNeeded() {}
        override fun onAddTrack(receiver: RtpReceiver, mediaStreams: Array<out MediaStream>) { (receiver.track() as? VideoTrack)?.let { attachVideo(it) } }
        private fun attachVideo(track: VideoTrack) {
            remoteVideoTrack = track
            runOnUiThread { if (viewerPeer != null) { track.addSink(videoRenderer); stopViewButton.isEnabled = true } }
        }
    }

    private fun stopLiveView(message: String) {
        val pc = viewerPeer; viewerPeer = null
        remoteVideoTrack?.removeSink(videoRenderer); remoteVideoTrack = null
        try { pc?.close() } catch (_: Exception) {}
        runOnUiThread { status.text = message; stopViewButton.isEnabled = false; if (::viewButton.isInitialized) viewButton.isEnabled = client != null && screenEnabled }
    }

    private fun openUploadPicker() {
        if (client == null) { showError("Connect first"); return }
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) }, pickUpload)
    }

    private fun saveSelected() {
        val index = files.checkedItemPosition
        if (index < 0 || index >= entries.size) { showError("Select a file first"); return }
        val item = entries[index]
        if (item.isDirectory) { showError("Folder navigation is not available in this alpha. Enter its path manually above."); return }
        downloadEntry = item
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE); type = "application/octet-stream"; putExtra(Intent.EXTRA_TITLE, item.name)
        }, pickSave)
    }

    @Deprecated("Activity result API kept simple for the alpha")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        val uri = data.data!!
        if (requestCode == pickUpload) uploadUri(uri)
        if (requestCode == pickSave) downloadToUri(uri)
    }

    private fun uploadUri(uri: Uri) {
        runAsync {
            val name = queryName(uri) ?: "upload.bin"
            val temp = File(cacheDir, "upload_${System.currentTimeMillis()}_${name.replace(Regex("[^A-Za-z0-9._-]"), "_")}")
            contentResolver.openInputStream(uri).use { input -> temp.outputStream().use { output -> input?.copyTo(output) ?: error("Could not read selected file") } }
            val body = temp.asRequestBody("application/octet-stream".toMediaType())
            val multipart = MultipartBody.Builder().setType(MultipartBody.FORM).addFormDataPart("files", name, body).build()
            val path = Uri.encode(remotePath.text.toString().trim(), "/")
            val response = client!!.newCall(request("/api/upload?path=$path").post(multipart).build()).execute()
            val text = response.body?.string().orEmpty(); temp.delete()
            if (!response.isSuccessful) error("Upload rejected (${response.code}): $text. Confirm uploads are enabled on the PC.")
            runOnUiThread { status.text = "Uploaded $name successfully"; refreshFiles() }
        }
    }

    private fun downloadToUri(uri: Uri) {
        val item = downloadEntry ?: return
        runAsync {
            val path = Uri.encode(listOf(remotePath.text.toString().trim(), item.name).filter { it.isNotEmpty() }.joinToString("/"), "/")
            val response = client!!.newCall(request("/api/download?path=$path").get().build()).execute()
            if (!response.isSuccessful) error("Download failed (${response.code})")
            val bytes = response.body?.bytes() ?: error("Empty response")
            contentResolver.openOutputStream(uri).use { it?.write(bytes) ?: error("Could not write selected destination") }
            runOnUiThread { status.text = "Saved ${item.name} to phone (${formatSize(bytes.size.toLong())})" }
        }
    }

    private fun queryName(uri: Uri): String? = contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (it.moveToFirst()) it.getString(0) else null
    }

    private fun runAsync(task: () -> Unit) {
        Thread {
            try { task() } catch (e: Exception) { showError(e.message ?: "Operation failed") }
        }.start()
    }
    override fun onDestroy() {
        stopLiveView("TYROX closed.")
        try { if (::videoRenderer.isInitialized) videoRenderer.release() } catch (_: Exception) {}
        try { peerFactory?.dispose() } catch (_: Exception) {}
        try { eglBase?.release() } catch (_: Exception) {}
        super.onDestroy()
    }
    private fun showError(message: String) = runOnUiThread { status.text = "Error: $message" }
    private fun formatSize(n: Long): String = when { n < 1024 -> "$n B"; n < 1024 * 1024 -> "%.1f KB".format(n / 1024.0); else -> "%.1f MB".format(n / (1024.0 * 1024.0)) }
}
