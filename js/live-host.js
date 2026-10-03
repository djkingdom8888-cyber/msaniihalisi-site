// Host console: captures the host's camera, composites it (plus any approved
// guest cameras) onto a canvas, and broadcasts that composed stream to every
// viewer over its own RTCPeerConnection. Signaling is relayed through the
// Flask-SocketIO server (see backend/app.py's webrtc_signal handler) — the
// server never touches media, only forwards SDP/ICE JSON between socket ids.
(function () {
  const ROOM = window.LIVE_ROOM;
  const socket = io();

  const canvas = document.getElementById("compose-canvas");
  // willReadFrequently: the filter pass below calls getImageData every frame
  // once live -- this hint keeps Chromium/WebKit from re-optimizing the
  // context for GPU compositing only, which would make that call much slower.
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const selfPreview = document.getElementById("self-preview");
  const goLiveBtn = document.getElementById("go-live-btn");
  const endLiveBtn = document.getElementById("end-live-btn");
  const camRequestsBox = document.getElementById("camera-requests");
  const chatMessages = document.getElementById("chat-messages");
  const chatInput = document.getElementById("chat-input");
  const chatSend = document.getElementById("chat-send");
  const statusBadge = document.getElementById("status-badge");
  const switchCameraBtn = document.getElementById("switch-camera-btn");
  const filterSelect = document.getElementById("filter-select");
  const cameraSourceBtn = document.getElementById("camera-source-btn");
  const screenShareBtn = document.getElementById("screen-share-btn");
  const videoFileBtn = document.getElementById("video-file-btn");
  const videoFileInput = document.getElementById("video-file-input");
  const screenSharePreview = document.getElementById("screen-share-preview");
  const videoFilePlayer = document.getElementById("video-file-player");

  // Filters used to be applied via ctx.filter = "<css filter string>" at
  // draw time. That property is unreliable on WebKit/iOS Safari -- multi-
  // function filter strings frequently render as a silent no-op there even
  // though the property exists, which is exactly the "picking a filter does
  // nothing" bug this replaces. To get identical, guaranteed behavior on
  // every platform (desktop, Safari, iOS, Android), each filter is instead
  // precomputed as a single 3x3 color matrix + bias (composing the whole
  // recipe -- saturate, contrast, brightness, etc, in order) and applied by
  // hand to the composited frame's raw pixels once per frame via
  // getImageData/putImageData. Pure arithmetic, no browser filter API
  // involved, so it can't silently fail to apply.
  function mulM(a, b) {
    const r = new Array(9);
    for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) {
      r[i * 3 + j] = a[i * 3 + 0] * b[0 * 3 + j] + a[i * 3 + 1] * b[1 * 3 + j] + a[i * 3 + 2] * b[2 * 3 + j];
    }
    return r;
  }
  function mulMV(m, v) { return [m[0] * v[0] + m[1] * v[1] + m[2] * v[2], m[3] * v[0] + m[4] * v[1] + m[5] * v[2], m[6] * v[0] + m[7] * v[1] + m[8] * v[2]]; }
  function addV(a, b) { return [a[0] + b[0], a[1] + b[1], a[2] + b[2]]; }
  // Composes "apply (M1,b1) first, then (M2,b2)" into one matrix/bias pair:
  // out = M2*(M1*x + b1) + b2 = (M2*M1)*x + (M2*b1 + b2)
  function compose(M2, b2, M1, b1) { return { M: mulM(M2, M1), b: addV(mulMV(M2, b1), b2) }; }
  const IDENTITY = [1, 0, 0, 0, 1, 0, 0, 0, 1];
  function brightnessOp(amt) { return { M: [amt, 0, 0, 0, amt, 0, 0, 0, amt], b: [0, 0, 0] }; }
  function contrastOp(amt) { const k = (1 - amt) * 128; return { M: [amt, 0, 0, 0, amt, 0, 0, 0, amt], b: [k, k, k] }; }
  function saturateOp(s) {
    return {
      M: [
        0.213 + 0.787 * s, 0.715 - 0.715 * s, 0.072 - 0.072 * s,
        0.213 - 0.213 * s, 0.715 + 0.285 * s, 0.072 - 0.072 * s,
        0.213 - 0.213 * s, 0.715 - 0.715 * s, 0.072 + 0.928 * s,
      ], b: [0, 0, 0],
    };
  }
  function grayscaleOp() { return { M: [0.2126, 0.7152, 0.0722, 0.2126, 0.7152, 0.0722, 0.2126, 0.7152, 0.0722], b: [0, 0, 0] }; }
  function sepiaOp(amt) {
    const full = [0.393, 0.769, 0.189, 0.349, 0.686, 0.168, 0.272, 0.534, 0.131];
    return { M: full.map((v, i) => IDENTITY[i] * (1 - amt) + v * amt), b: [0, 0, 0] };
  }
  function hueRotateOp(deg) {
    const a = (deg * Math.PI) / 180, c = Math.cos(a), s = Math.sin(a);
    return {
      M: [
        0.213 + c * 0.787 - s * 0.213, 0.715 - c * 0.715 - s * 0.715, 0.072 - c * 0.072 + s * 0.928,
        0.213 - c * 0.213 + s * 0.143, 0.715 + c * 0.285 + s * 0.140, 0.072 - c * 0.072 - s * 0.283,
        0.213 - c * 0.213 - s * 0.787, 0.715 - c * 0.715 + s * 0.715, 0.072 + c * 0.928 + s * 0.072,
      ], b: [0, 0, 0],
    };
  }
  function chainOps(ops) {
    let cur = { M: IDENTITY, b: [0, 0, 0] };
    for (const op of ops) cur = compose(op.M, op.b, cur.M, cur.b);
    return cur;
  }
  // Same recipes as before (matching the original CSS filter strings), minus
  // dreamy's blur(0.4px) -- too subtle to matter and not worth a per-frame
  // convolution pass; the color grade is what actually reads as "dreamy".
  const FILTER_OPS = {
    none: null,
    vivid: chainOps([saturateOp(1.5), contrastOp(1.12), brightnessOp(1.03)]),
    mono: chainOps([grayscaleOp(), contrastOp(1.1)]),
    noir: chainOps([grayscaleOp(), contrastOp(1.45), brightnessOp(0.92)]),
    warm: chainOps([sepiaOp(0.35), saturateOp(1.35), brightnessOp(1.05)]),
    cool: chainOps([saturateOp(1.15), hueRotateOp(-8), brightnessOp(1.02), contrastOp(1.05)]),
    dreamy: chainOps([brightnessOp(1.1), contrastOp(0.92), saturateOp(1.15)]),
  };
  function clamp255(v) { return v < 0 ? 0 : v > 255 ? 255 : v; }
  function applyFrameFilter(name) {
    const op = FILTER_OPS[name];
    if (!op) return; // "none" (or an unrecognized name) -- leave the frame untouched
    const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const d = frame.data;
    const M = op.M, b = op.b;
    const m0 = M[0], m1 = M[1], m2 = M[2], m3 = M[3], m4 = M[4], m5 = M[5], m6 = M[6], m7 = M[7], m8 = M[8];
    const b0 = b[0], b1 = b[1], b2 = b[2];
    for (let i = 0; i < d.length; i += 4) {
      const r = d[i], g = d[i + 1], bl = d[i + 2];
      d[i] = clamp255(m0 * r + m1 * g + m2 * bl + b0);
      d[i + 1] = clamp255(m3 * r + m4 * g + m5 * bl + b1);
      d[i + 2] = clamp255(m6 * r + m7 * g + m8 * bl + b2);
    }
    ctx.putImageData(frame, 0, 0);
  }
  let currentFilter = filterSelect ? filterSelect.value : "vivid";
  let currentFacingMode = "user"; // "user" = front/selfie camera, "environment" = back camera

  let hostStream = null;
  let finalStream = null; // composed video (canvas) + mixed audio, sent to viewers & recorded
  let audioCtx = null;
  let mixDestination = null;
  // Every approved guest gets its own RTCPeerConnection + hidden <video> element,
  // keyed by socket id. The draw loop below tiles however many of these are
  // currently connected (plus the host) into a grid, Zoom/Meet-style.
  const guestConnections = new Map(); // sid -> { pc, video, name }
  // A requester's peer connection is live (so the host can preview them)
  // before any approve/decline decision is made. Entries here are NOT drawn
  // to the canvas and their audio is NOT mixed into the broadcast -- only
  // approveGuest() promotes an entry into guestConnections, at which point it
  // starts appearing for viewers.
  const pendingGuests = new Map(); // sid -> { pc, video, name, requestId, stream }
  const viewerConnections = {}; // sid -> RTCPeerConnection (host is offerer, broadcasting finalStream)
  let mediaRecorder = null;
  let recordedChunks = [];
  let chunkUploadQueue = Promise.resolve();
  let chunkUploadFailures = 0;
  let isLive = false;

  // Retries so one dropped request (brief network blip) costs nothing --
  // it's a ~1s chunk, not the whole session. Giving up after retries still
  // only loses that one chunk; everything else already uploaded is safe.
  async function uploadChunk(blob, attempt = 1) {
    const form = new FormData();
    form.append("chunk", blob, "chunk.webm");
    try {
      const res = await fetch(`/live/${ROOM}/upload-chunk`, { method: "POST", body: form });
      if (!res.ok) throw new Error("chunk upload failed: " + res.status);
    } catch (e) {
      if (attempt < 3) {
        await new Promise((r) => setTimeout(r, 500 * attempt));
        return uploadChunk(blob, attempt + 1);
      }
      chunkUploadFailures++;
    }
  }

  function appendChatLine(name, message) {
    const div = document.createElement("div");
    div.className = "msg";
    div.innerHTML = `<strong>${escapeHtml(name)}</strong>${escapeHtml(message)}`;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // ---------------- Camera + canvas compositing loop ----------------
  async function initCamera() {
    hostStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: currentFacingMode } },
      audio: true,
    });
    selfPreview.srcObject = hostStream;

    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    mixDestination = audioCtx.createMediaStreamDestination();
    audioCtx.createMediaStreamSource(hostStream).connect(mixDestination);

    const canvasStream = canvas.captureStream(30);
    finalStream = new MediaStream([
      ...canvasStream.getVideoTracks(),
      ...mixDestination.stream.getAudioTracks(),
    ]);

    drawLoop();
  }

  // Swaps the host's own camera between front/back. This never needs to touch
  // any RTCPeerConnection: what viewers actually receive is the CANVAS's
  // captured stream, and the canvas just draws whatever `selfPreview` shows
  // right now -- so re-pointing selfPreview at a new video track is the whole
  // fix. The mic (and the AudioContext node already wired to it) is left
  // completely alone.
  async function switchCamera() {
    if (!hostStream) return;
    const nextFacing = currentFacingMode === "user" ? "environment" : "user";
    switchCameraBtn.disabled = true;
    try {
      const newVideoStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: nextFacing } },
      });
      const newTrack = newVideoStream.getVideoTracks()[0];
      const oldTrack = hostStream.getVideoTracks()[0];
      hostStream.removeTrack(oldTrack);
      oldTrack.stop();
      hostStream.addTrack(newTrack);
      selfPreview.srcObject = hostStream; // re-assign so the element notices the swap
      currentFacingMode = nextFacing;
    } catch (err) {
      alert("Couldn't switch camera: " + err.message);
    } finally {
      switchCameraBtn.disabled = false;
    }
  }
  switchCameraBtn.onclick = switchCamera;

  if (filterSelect) {
    filterSelect.onchange = () => { currentFilter = filterSelect.value; };
  }

  // ---------------- Main broadcast source: camera / screen share / video file ----------------
  // Whichever of these is "active" supplies tile 0 of the composited grid
  // (see drawLoop below) -- guest cameras still tile on top of it exactly as
  // they do over the plain camera, since tile 0 is just swapped out, nothing
  // else about the compositing loop changes. Because viewers only ever
  // receive the CANVAS's captured stream (same fact switchCamera() above
  // relies on), none of this needs any RTCPeerConnection renegotiation --
  // swapping the source is purely local to the draw loop.
  let activeMainSource = "camera"; // "camera" | "screen" | "video"
  let screenStream = null;
  let screenShareAudioNode = null;
  let videoFileAudioNode = null;
  let currentVideoFileUrl = null;
  let currentVideoFileName = "Video";
  const supportsDisplayMedia = !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);
  if (!supportsDisplayMedia && screenShareBtn) {
    screenShareBtn.disabled = true;
    screenShareBtn.title = "Screen share isn't supported in this browser";
  }

  function updateSourceButtons() {
    cameraSourceBtn.classList.toggle("active", activeMainSource === "camera");
    screenShareBtn.classList.toggle("active", activeMainSource === "screen");
    videoFileBtn.classList.toggle("active", activeMainSource === "video");
    screenShareBtn.textContent = activeMainSource === "screen" ? "Stop screen share" : "Share screen";
    videoFileBtn.textContent = activeMainSource === "video" ? "Stop video" : "Play video file";
  }

  // Lazily brings up the camera/mic + canvas capture + audio mix graph the
  // first time ANY source control is used, not just "Go live" -- a host
  // should be able to set up screen share or cue a video file before going
  // live, same as picking a filter already works pre-broadcast.
  async function ensureMediaReady() {
    if (hostStream) return;
    await initCamera();
  }

  // getDisplayMedia() captures whatever window/tab/screen the host picks --
  // including a YouTube tab playing in their own browser. This is the real,
  // supported way to "cast video" into the broadcast; there is no way to
  // capture a cross-origin <iframe>'s video directly (browsers block that
  // entirely), so screen share is the actual mechanism for that use case.
  async function startScreenShare() {
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
      stopVideoFilePlayback(); // sources are mutually exclusive for tile 0
      screenStream = stream;
      screenSharePreview.srcObject = stream;
      activeMainSource = "screen";
      updateSourceButtons();

      const audioTracks = stream.getAudioTracks();
      if (audioTracks.length) {
        screenShareAudioNode = audioCtx.createMediaStreamSource(new MediaStream(audioTracks));
        screenShareAudioNode.connect(mixDestination);
      }

      // Browser's native "Stop sharing" UI ends the video track directly --
      // this is the only reliable signal that happened, so fall back to the
      // camera from here rather than leaving the canvas drawing a dead tile.
      stream.getVideoTracks()[0].onended = () => stopScreenShare();
    } catch (err) {
      // NotAllowedError/AbortError = the host just dismissed the picker; not
      // worth alarming them with an error dialog for that.
      if (err && err.name !== "NotAllowedError" && err.name !== "AbortError") {
        alert("Couldn't start screen share: " + err.message);
      }
    }
  }

  function stopScreenShare() {
    if (screenStream) {
      screenStream.getTracks().forEach((t) => t.stop());
      screenStream = null;
    }
    screenSharePreview.srcObject = null;
    if (screenShareAudioNode) {
      try { screenShareAudioNode.disconnect(); } catch (e) { /* already disconnected */ }
      screenShareAudioNode = null;
    }
    if (activeMainSource === "screen") {
      activeMainSource = "camera";
      updateSourceButtons();
    }
  }

  // Plays a host-picked local video file into the broadcast. The visual side
  // reuses the exact same drawImage/drawCover path the camera tiles already
  // use (see getMainTile() + drawLoop below) rather than captureStream'ing
  // the whole element -- matching how this file already draws every other
  // video source onto the canvas. captureStream() IS used, narrowly, just to
  // get a tappable MediaStream for the file's AUDIO track, mixed into
  // mixDestination the same non-destructive way guest audio already is
  // (see approveGuest() above) -- unlike Web Audio's MediaElementSourceNode,
  // this doesn't hijack the <video> element's own output, so it keeps
  // playing/monitoring normally too.
  function startVideoFilePlayback(file) {
    stopScreenShare();
    if (currentVideoFileUrl) URL.revokeObjectURL(currentVideoFileUrl);
    currentVideoFileUrl = URL.createObjectURL(file);
    currentVideoFileName = file.name.replace(/\.[^./]+$/, "") || "Video";
    videoFilePlayer.src = currentVideoFileUrl;
    videoFilePlayer.currentTime = 0;
    videoFilePlayer.play().then(() => {
      activeMainSource = "video";
      updateSourceButtons();
      try {
        const captured = videoFilePlayer.captureStream
          ? videoFilePlayer.captureStream()
          : videoFilePlayer.mozCaptureStream();
        const audioTracks = captured.getAudioTracks();
        if (audioTracks.length) {
          videoFileAudioNode = audioCtx.createMediaStreamSource(new MediaStream(audioTracks));
          videoFileAudioNode.connect(mixDestination);
        }
      } catch (e) {
        // captureStream() unsupported on this browser -- the file still
        // plays visually in the broadcast, just without its own audio track.
      }
    }).catch((err) => {
      alert("Couldn't play that video file: " + err.message);
      stopVideoFilePlayback();
    });
  }

  // Video ending on its own (reached the end) needs the exact same cleanup
  // as the host manually stopping it -- requirement is "don't leave the
  // broadcast frozen," so always fall back to camera here too.
  videoFilePlayer.addEventListener("ended", () => stopVideoFilePlayback());

  function stopVideoFilePlayback() {
    videoFilePlayer.pause();
    videoFilePlayer.removeAttribute("src");
    videoFilePlayer.load();
    if (currentVideoFileUrl) {
      URL.revokeObjectURL(currentVideoFileUrl);
      currentVideoFileUrl = null;
    }
    if (videoFileAudioNode) {
      try { videoFileAudioNode.disconnect(); } catch (e) { /* already disconnected */ }
      videoFileAudioNode = null;
    }
    if (activeMainSource === "video") {
      activeMainSource = "camera";
      updateSourceButtons();
    }
  }

  cameraSourceBtn.onclick = async () => {
    await ensureMediaReady();
    stopScreenShare();
    stopVideoFilePlayback();
    activeMainSource = "camera";
    updateSourceButtons();
  };

  screenShareBtn.onclick = async () => {
    if (activeMainSource === "screen") { stopScreenShare(); return; }
    await ensureMediaReady();
    startScreenShare();
  };

  videoFileBtn.onclick = async () => {
    if (activeMainSource === "video") { stopVideoFilePlayback(); return; }
    await ensureMediaReady();
    videoFileInput.click();
  };

  videoFileInput.onchange = async () => {
    const file = videoFileInput.files[0];
    videoFileInput.value = "";
    if (!file) return;
    await ensureMediaReady();
    startVideoFilePlayback(file);
  };

  // Which element supplies tile 0 right now. Guests still tile on top
  // regardless of which of these is active -- drawLoop pushes this as the
  // first tile, then appends guestConnections exactly as it always did.
  function getMainTile() {
    if (activeMainSource === "screen" && screenSharePreview.srcObject) {
      return { el: screenSharePreview, name: "Screen share" };
    }
    if (activeMainSource === "video" && videoFilePlayer.src) {
      return { el: videoFilePlayer, name: currentVideoFileName };
    }
    return { el: selfPreview, name: window.HOST_NAME || "Host" };
  }

  updateSourceButtons();

  // "Cover"-style draw (like CSS object-fit: cover): fills the target cell
  // without squishing the source video's aspect ratio, cropping instead.
  function drawCover(videoEl, x, y, w, h) {
    const vw = videoEl.videoWidth, vh = videoEl.videoHeight;
    if (!vw || !vh) return;
    const scale = Math.max(w / vw, h / vh);
    const sw = w / scale, sh = h / scale;
    const sx = (vw - sw) / 2, sy = (vh - sh) / 2;
    ctx.drawImage(videoEl, sx, sy, sw, sh, x, y, w, h);
  }

  function drawLoop() {
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Tile 0 is whichever main source is active (camera / screen share /
    // video file). Every connected guest adds another tile — the grid
    // reflows live as people join or leave, no fixed layout.
    const tiles = [getMainTile()];
    guestConnections.forEach((g) => tiles.push({ el: g.video, name: g.name || "Guest" }));

    const total = tiles.length;
    const cols = Math.ceil(Math.sqrt(total));
    const rows = Math.ceil(total / cols);
    const cellW = canvas.width / cols;
    const cellH = canvas.height / rows;

    tiles.forEach((tile, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const x = col * cellW;
      const y = row * cellH;
      if (tile.el.readyState >= 2) {
        drawCover(tile.el, x, y, cellW, cellH);
      }
      ctx.save();
      ctx.strokeStyle = i === 0 ? "rgba(242,233,216,0.3)" : "#B23A22";
      ctx.lineWidth = 2;
      ctx.strokeRect(x + 1, y + 1, cellW - 2, cellH - 2);
      ctx.font = "16px Inter, sans-serif";
      ctx.fillStyle = "rgba(0,0,0,0.55)";
      const labelW = ctx.measureText(tile.name).width + 16;
      ctx.fillRect(x + 8, y + cellH - 32, labelW, 24);
      ctx.fillStyle = "#F2E9D8";
      ctx.fillText(tile.name, x + 16, y + cellH - 14);
      ctx.restore();
    });

    // Applied once to the whole composited frame (grid + borders + labels)
    // rather than per-tile before -- one getImageData/putImageData pass is
    // far cheaper than N of them, and still applies to every guest tile
    // automatically since it runs after all of them are drawn.
    applyFrameFilter(currentFilter);

    requestAnimationFrame(drawLoop);
  }

  // ---------------- Broadcasting to viewers ----------------
  function createViewerConnection(viewerSid) {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    finalStream.getTracks().forEach((track) => pc.addTrack(track, finalStream));
    pc.onicecandidate = (e) => {
      if (e.candidate) {
        socket.emit("webrtc_signal", { to: viewerSid, kind: "broadcast", type: "ice", candidate: e.candidate });
      }
    };
    viewerConnections[viewerSid] = pc;
    pc.createOffer().then((offer) => {
      pc.setLocalDescription(offer);
      socket.emit("webrtc_signal", { to: viewerSid, kind: "broadcast", type: "offer", sdp: offer });
    });
    return pc;
  }

  // ---------------- Guest cameras (viewer -> host), one connection per guest ----------------
  // The peer connection is established as soon as a request comes in, NOT on
  // approval -- this is what lets the host actually see/hear the requester
  // (via the visible preview video in the request row) before deciding.
  // Nothing here reaches viewers yet: the video element isn't drawn by
  // drawLoop and the audio isn't wired into mixDestination until approveGuest()
  // promotes the entry into guestConnections.
  // No TURN server is configured (STUN only) -- a requester on a different
  // network than the host (especially cellular/mobile data, which almost
  // always sits behind carrier-grade NAT) can fail to connect here even
  // though the request/signaling itself worked perfectly. Without this
  // watchdog, that failure was invisible: the request row just showed a
  // permanently blank video with a live Approve button, so a host could
  // approve someone whose video/audio never actually arrived -- exactly the
  // "host couldn't see the client" failure mode reported in production.
  const GUEST_CONNECTION_TIMEOUT_MS = 12000;

  function handleGuestOffer(fromSid, sdp, name, requestId) {
    if (pendingGuests.has(fromSid) || guestConnections.has(fromSid)) return; // duplicate offer, ignore

    const video = document.createElement("video");
    video.autoplay = true;
    video.playsInline = true;
    video.muted = false; // host can hear the requester too while deciding

    const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    let connectTimer = null;
    pc.onicecandidate = (e) => {
      if (e.candidate) {
        socket.emit("webrtc_signal", { to: fromSid, kind: "guest", type: "ice", candidate: e.candidate });
      }
    };
    pc.ontrack = (e) => {
      video.srcObject = e.streams[0];
      const entry = pendingGuests.get(fromSid) || guestConnections.get(fromSid);
      if (entry) entry.stream = e.streams[0];
      clearTimeout(connectTimer);
      setRequestRowStatus(fromSid, "live", "Live preview");
    };
    const onIceStateChange = () => {
      if (pc.iceConnectionState === "failed") {
        clearTimeout(connectTimer);
        setRequestRowStatus(fromSid, "failed", "⚠ Couldn't connect — likely a network issue on their end");
      }
    };
    pc.oniceconnectionstatechange = onIceStateChange;
    pc.onconnectionstatechange = () => {
      if (["disconnected", "failed", "closed"].includes(pc.connectionState)) {
        removeAnyGuest(fromSid);
      }
    };

    pendingGuests.set(fromSid, { pc, video, name, requestId });

    pc.setRemoteDescription(new RTCSessionDescription(sdp)).then(() => {
      return pc.createAnswer();
    }).then((answer) => {
      pc.setLocalDescription(answer);
      socket.emit("webrtc_signal", { to: fromSid, kind: "guest", type: "guest-answer", sdp: answer });
    });

    renderCameraRequestRow(fromSid, name, requestId, video);
    connectTimer = setTimeout(() => {
      if (!video.srcObject) {
        setRequestRowStatus(fromSid, "failed", "⚠ Still connecting — their video/audio hasn't arrived yet, may be a network issue");
      }
    }, GUEST_CONNECTION_TIMEOUT_MS);
  }

  // Host clicked "Approve": the connection is already live, so this just
  // promotes it into the set drawLoop composites and wires its audio into the
  // broadcast mix -- nothing needs to be renegotiated.
  function approveGuest(sid) {
    const entry = pendingGuests.get(sid);
    if (!entry) return;
    pendingGuests.delete(sid);
    entry.video.style.display = "none";
    document.body.appendChild(entry.video); // keep playing, out of the (removed) request row
    if (entry.stream) {
      audioCtx.createMediaStreamSource(entry.stream).connect(mixDestination);
    }
    guestConnections.set(sid, { pc: entry.pc, video: entry.video, name: entry.name });
  }

  // Host clicked "Decline": tear down the preview connection. Nothing was
  // ever broadcast, so there's nothing else to undo.
  function declineGuest(sid) {
    const entry = pendingGuests.get(sid);
    if (!entry) return;
    pendingGuests.delete(sid);
    try { entry.pc.close(); } catch (e) { /* already closed */ }
  }

  function removeGuest(sid) {
    const g = guestConnections.get(sid);
    if (!g) return;
    try { g.pc.close(); } catch (e) { /* already closed */ }
    if (g.video.parentNode) g.video.parentNode.removeChild(g.video);
    guestConnections.delete(sid);
  }

  // Connection dropped before a decision was ever made (pending) vs. after
  // approval (already live in the broadcast) need different cleanup.
  function removeAnyGuest(sid) {
    if (pendingGuests.has(sid)) {
      const entry = pendingGuests.get(sid);
      pendingGuests.delete(sid);
      try { entry.pc.close(); } catch (e) { /* already closed */ }
      const row = document.getElementById(`cam-req-${sid}`);
      if (row) row.remove();
    } else {
      removeGuest(sid);
    }
  }

  function setRequestRowStatus(sid, state, text) {
    const row = document.getElementById(`cam-req-${sid}`);
    if (!row) return;
    row.dataset.connectionState = state;
    const status = row.querySelector(".camera-request-status");
    if (status) {
      status.textContent = text;
      status.className = "camera-request-status" + (state === "failed" ? " warn" : state === "live" ? " ok" : "");
    }
  }

  function renderCameraRequestRow(sid, name, requestId, videoEl) {
    const row = document.createElement("div");
    row.className = "camera-request-row";
    row.id = `cam-req-${sid}`;

    videoEl.className = "camera-preview-video";
    row.appendChild(videoEl);

    const infoWrap = document.createElement("span");
    infoWrap.className = "camera-request-info";
    const info = document.createElement("span");
    info.textContent = `${name} would like to join on camera`;
    const status = document.createElement("span");
    status.className = "camera-request-status";
    status.textContent = "Connecting…";
    infoWrap.appendChild(info);
    infoWrap.appendChild(document.createElement("br"));
    infoWrap.appendChild(status);
    row.appendChild(infoWrap);
    row.dataset.connectionState = "connecting";

    const actions = document.createElement("span");
    actions.className = "actions";

    const approveBtn = document.createElement("button");
    approveBtn.className = "btn btn-sm";
    approveBtn.textContent = "Approve";
    approveBtn.onclick = () => {
      if (row.dataset.connectionState !== "live") {
        const proceed = confirm(
          "No video/audio has come through from this person yet (possible network issue on their end). Approve anyway?"
        );
        if (!proceed) return;
      }
      socket.emit("respond_camera", { room: ROOM, request_id: requestId, approve: true });
      approveGuest(sid);
      row.remove();
    };

    const denyBtn = document.createElement("button");
    denyBtn.className = "btn btn-outline btn-sm";
    denyBtn.textContent = "Decline";
    denyBtn.style.marginLeft = "6px";
    denyBtn.onclick = () => {
      socket.emit("respond_camera", { room: ROOM, request_id: requestId, approve: false });
      declineGuest(sid);
      row.remove();
    };

    actions.appendChild(approveBtn);
    actions.appendChild(denyBtn);
    row.appendChild(actions);
    camRequestsBox.appendChild(row);
  }

  // ---------------- Socket events ----------------
  socket.on("connect", () => {
    socket.emit("join_room", { room: ROOM, role: "host", name: window.HOST_NAME });
  });

  socket.on("presence", (data) => {
    if (data.role === "viewer" && isLive && finalStream && data.sid && !viewerConnections[data.sid]) {
      createViewerConnection(data.sid);
    }
  });

  socket.on("webrtc_signal", (data) => {
    if (data.kind === "broadcast" && data.type === "answer") {
      const pc = viewerConnections[data.from];
      if (pc) pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
    } else if (data.kind === "broadcast" && data.type === "ice") {
      const pc = viewerConnections[data.from];
      if (pc) pc.addIceCandidate(new RTCIceCandidate(data.candidate)).catch(() => {});
    } else if (data.kind === "guest" && data.type === "ice") {
      const entry = pendingGuests.get(data.from) || guestConnections.get(data.from);
      if (entry) entry.pc.addIceCandidate(new RTCIceCandidate(data.candidate)).catch(() => {});
    }
  });

  socket.on("chat_history", (data) => {
    chatMessages.innerHTML = "";
    (data.messages || []).forEach((m) => appendChatLine(m.sender_name, m.message));
  });
  socket.on("chat_message", (data) => appendChatLine(data.name, data.message));

  socket.on("camera_offer", (data) => {
    handleGuestOffer(data.socket_id, data.sdp, data.name, data.request_id);
  });

  // ---------------- Controls ----------------
  chatSend.onclick = sendChat;
  chatInput.addEventListener("keydown", (e) => { if (e.key === "Enter") sendChat(); });
  function sendChat() {
    const message = chatInput.value.trim();
    if (!message) return;
    socket.emit("chat_message", { room: ROOM, name: window.HOST_NAME, message });
    chatInput.value = "";
  }

  // Same iOS issue as the viewer side: the host's own phone can auto-lock
  // mid-broadcast, and WebKit suspends the page the instant that happens --
  // killing the camera, the broadcast, everything. Hold a Screen Wake Lock
  // for the entire time the host is live, same API/pattern as live-viewer.js
  // (see that file for the full explanation).
  let hostWakeLock = null;
  let hostWantWakeLock = false;

  async function acquireHostWakeLock() {
    hostWantWakeLock = true;
    if (!("wakeLock" in navigator) || hostWakeLock) return;
    try {
      hostWakeLock = await navigator.wakeLock.request("screen");
      hostWakeLock.addEventListener("release", () => { hostWakeLock = null; });
    } catch (e) {
      // Not supported, or denied (e.g. Low Power Mode) -- nothing else we
      // can do client-side.
    }
  }

  function releaseHostWakeLock() {
    hostWantWakeLock = false;
    if (hostWakeLock) { hostWakeLock.release().catch(() => {}); hostWakeLock = null; }
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && hostWantWakeLock) acquireHostWakeLock();
  });

  goLiveBtn.onclick = async () => {
    goLiveBtn.disabled = true;
    goLiveBtn.textContent = "Starting…";
    try {
      if (!hostStream) await initCamera();
      isLive = true;
      acquireHostWakeLock();
      socket.emit("host_go_live", { room: ROOM });
      statusBadge.textContent = "LIVE";
      statusBadge.className = "status-badge live";
      goLiveBtn.style.display = "none";
      endLiveBtn.disabled = false;

      // Each ~1s chunk is uploaded to the server as it's produced (see
      // backend's /upload-chunk for why) instead of being buffered here
      // until "end live" -- a chunk queue + sequential uploader keeps
      // chunks in order on the server even though MediaRecorder can fire
      // ondataavailable faster than any one upload completes.
      recordedChunks = [];
      chunkUploadQueue = Promise.resolve();
      mediaRecorder = new MediaRecorder(finalStream, { mimeType: "video/webm;codecs=vp8,opus" });
      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size === 0) return;
        recordedChunks.push(e.data); // local fallback only, see endLiveBtn.onclick
        chunkUploadQueue = chunkUploadQueue.then(() => uploadChunk(e.data));
      };
      mediaRecorder.start(1000);
    } catch (err) {
      alert("Couldn't access camera/microphone: " + err.message);
      goLiveBtn.disabled = false;
      goLiveBtn.textContent = "Go live";
    }
  };

  endLiveBtn.onclick = async () => {
    endLiveBtn.disabled = true;
    endLiveBtn.textContent = "Saving…";
    isLive = false;
    releaseHostWakeLock();
    socket.emit("host_end_live", { room: ROOM });
    statusBadge.textContent = "ENDED";
    statusBadge.className = "status-badge ended";
    Object.values(viewerConnections).forEach((pc) => pc.close());
    Array.from(guestConnections.keys()).forEach(removeGuest);
    Array.from(pendingGuests.keys()).forEach(declineGuest);
    camRequestsBox.innerHTML = "";
    stopScreenShare();
    stopVideoFilePlayback();

    if (mediaRecorder && mediaRecorder.state !== "inactive") {
      await new Promise((resolve) => {
        mediaRecorder.onstop = resolve;
        mediaRecorder.stop();
      });
    }
    if (recordedChunks.length) {
      endLiveBtn.textContent = "Saving…";
      // Wait for every queued chunk upload (including retries) to finish --
      // most of the recording is on disk already from during the broadcast,
      // this just waits for the tail end and then tells the server to stitch
      // the chunks into the final file.
      await chunkUploadQueue;
      const finalizeRes = await fetch(`/live/${ROOM}/finalize-recording`, { method: "POST" }).catch(() => null);
      const finalizeData = finalizeRes ? await finalizeRes.json().catch(() => ({})) : {};
      if (finalizeRes && finalizeRes.ok) {
        endLiveBtn.textContent = chunkUploadFailures > 0
          ? `Saved (${chunkUploadFailures} chunk${chunkUploadFailures === 1 ? "" : "s"} dropped)`
          : "Saved";
      } else {
        endLiveBtn.textContent = "Save failed: " + (finalizeData.error || "unknown error");
      }
    } else {
      endLiveBtn.textContent = "Ended";
    }
  };
})();
