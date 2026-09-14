// /live listing page: without this, the page is fully static -- it computes
// live/scheduled/ended once server-side at request time and never updates,
// so a viewer who already has this page open when the host goes live sees
// zero indication of it until they manually reload.
//
// Polling (instead of a Socket.IO connection) on purpose: this is a public
// listing page anyone can browse without joining a room, so it shouldn't
// require every visitor to hold open a live socket just to look at a list.
// A short poll interval is simple, doesn't need a server-side broadcast
// hook beyond a small read-only JSON endpoint, and a status change showing
// up within ~10 seconds is plenty responsive for "is anyone live right now".
(function () {
  const POLL_MS = 9000;

  const grids = {
    live: document.getElementById("live-now-grid"),
    scheduled: document.getElementById("scheduled-grid"),
    ended: document.getElementById("ended-grid"),
  };
  const empties = {
    live: document.getElementById("live-now-empty"),
    scheduled: document.getElementById("scheduled-empty"),
    ended: document.getElementById("ended-empty"),
  };

  // id -> status, seeded from what the server rendered so the very first
  // poll doesn't mistake "already live when I opened this page" for
  // "just went live" and pop a banner immediately.
  let known = {};
  (window.LIVE_INITIAL_STATE || []).forEach((s) => {
    known[s.id] = s.status;
  });

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function cardHtml(s, section) {
    const host = escapeHtml(s.host_name || "Msanii Halisi");
    const title = escapeHtml(s.title);
    if (section === "live") {
      return `<div class="card" data-id="${s.id}"><span class="badge live"><span class="dot"></span> Live</span><h4>${title}</h4><p>Hosted by ${host}</p><a class="enter" href="/live/${s.room_code}">Join the room &rarr;</a></div>`;
    }
    if (section === "scheduled") {
      return `<div class="card" data-id="${s.id}"><span class="badge scheduled">Scheduled</span><h4>${title}</h4><p>Hosted by ${host}</p><a class="enter" href="/live/${s.room_code}">Reserve your seat &rarr;</a></div>`;
    }
    return `<div class="card" data-id="${s.id}"><span class="badge replay">Replay</span><h4>${title}</h4><p>Hosted by ${host}</p><a class="enter" href="/live/${s.room_code}/replay">Watch the replay &rarr;</a></div>`;
  }

  let banner = null;
  function showJustWentLiveBanner(title) {
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "live-banner";
      banner.style.cssText =
        "position:fixed;top:18px;left:50%;transform:translateX(-50%);" +
        "background:var(--rust);color:var(--bone);padding:12px 22px;" +
        "font-size:13px;font-weight:700;letter-spacing:0.3px;z-index:300;" +
        "box-shadow:0 6px 24px rgba(0,0,0,0.4);cursor:pointer;max-width:90vw;text-align:center;";
      banner.title = "Click to dismiss";
      banner.addEventListener("click", () => {
        banner.remove();
        banner = null;
      });
      document.body.appendChild(banner);
    }
    banner.textContent = `🔴 ${title} just went live`;
    clearTimeout(banner._dismissTimer);
    banner._dismissTimer = setTimeout(() => {
      if (banner) { banner.remove(); banner = null; }
    }, 8000);
  }

  async function poll() {
    let data;
    try {
      const res = await fetch("/api/live/status", { cache: "no-store" });
      if (!res.ok) return;
      data = await res.json();
    } catch (e) {
      return; // transient network hiccup -- just try again next tick
    }

    const buckets = { live: [], scheduled: [], ended: [] };
    data.forEach((s) => {
      if (s.status === "live") buckets.live.push(s);
      else if (s.status === "scheduled") buckets.scheduled.push(s);
      else if (s.status === "ended" && s.has_replay) buckets.ended.push(s);
    });

    buckets.live.forEach((s) => {
      if (known[s.id] !== "live") showJustWentLiveBanner(s.title);
    });

    ["live", "scheduled", "ended"].forEach((section) => {
      const grid = grids[section];
      const empty = empties[section];
      const list = buckets[section];
      if (!grid) return;
      grid.innerHTML = list.map((s) => cardHtml(s, section)).join("");
      grid.style.display = list.length ? "" : "none";
      if (empty) empty.style.display = list.length ? "none" : "";
    });

    known = {};
    data.forEach((s) => { known[s.id] = s.status; });
  }

  setInterval(poll, POLL_MS);
})();
