"use strict";

const $ = (sel) => document.querySelector(sel);
const body = $("#flows-body");
let selectedId = null;
let current = null; // seçili akışın detayı

// ---- History ----------------------------------------------------------
async function loadFlows() {
  const q = $("#search").value.trim();
  const url = "/api/flows?limit=300" + (q ? "&q=" + encodeURIComponent(q) : "");
  const res = await fetch(url);
  const data = await res.json();
  renderFlows(data.flows);
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}
function statusClass(code) {
  if (!code) return "s-err";
  return "s-" + String(code)[0];
}

function renderFlows(flows) {
  body.innerHTML = "";
  for (const f of flows) {
    const tr = document.createElement("tr");
    if (f.id === selectedId) tr.classList.add("sel");
    const status = f.error ? "ERR" : (f.status_code ?? "—");
    tr.innerHTML = `
      <td>${f.id}</td>
      <td>${fmtTime(f.created_at)}</td>
      <td class="${f.source === "repeater" ? "src-repeater" : ""}">${f.source}</td>
      <td class="m-${f.method}">${f.method}</td>
      <td title="${f.host}">${f.host}</td>
      <td title="${escapeHtml(f.path)}">${escapeHtml(f.path)}</td>
      <td class="${f.error ? "s-err" : statusClass(f.status_code)}">${status}</td>
      <td>${f.resp_size ?? "—"}</td>
      <td>${f.duration_ms != null ? Math.round(f.duration_ms) : "—"}</td>`;
    tr.onclick = () => selectFlow(f.id);
    body.appendChild(tr);
  }
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// ---- Detay -------------------------------------------------------------
async function selectFlow(id) {
  selectedId = id;
  const res = await fetch("/api/flows/" + id);
  if (!res.ok) return;
  current = await res.json();
  renderDetail(current);
  for (const tr of body.querySelectorAll("tr")) tr.classList.remove("sel");
  // seçili satırı işaretle
  for (const tr of body.querySelectorAll("tr")) {
    if (tr.firstElementChild && tr.firstElementChild.textContent == String(id)) tr.classList.add("sel");
  }
  loadRepeaterFrom(current);
}

function headersToText(headers) {
  return headers.map(([k, v]) => `${k}: ${v}`).join("\n");
}

function bodyToText(b) {
  if (!b || b.size === 0) return "";
  if (b.text != null) return b.text;
  return `[ikili veri, ${b.size} bayt — base64]\n` + (b.base64 || "");
}

function renderDetail(f) {
  const reqLine = `${f.method} ${f.path} ${f.http_version || "HTTP/1.1"}`;
  $("#req-view").textContent =
    reqLine + "\n" + headersToText(f.req_headers) + "\n\n" + bodyToText(f.req_body);

  if (f.error) {
    $("#resp-view").textContent = "HATA: " + f.error;
  } else {
    const statusLine = `${f.http_version || "HTTP/1.1"} ${f.status_code ?? ""} ${f.reason ?? ""}`;
    $("#resp-view").textContent =
      statusLine + "\n" + headersToText(f.resp_headers) + "\n\n" + bodyToText(f.resp_body);
  }
}

// ---- Repeater ----------------------------------------------------------
function loadRepeaterFrom(f) {
  $("#rep-method").value = f.method;
  $("#rep-url").value = f.url;
  // Proxy katmanına özgü başlıkları ayıklama; kullanıcı elle düzenlesin.
  $("#rep-headers").value = headersToText(f.req_headers);
  $("#rep-body").value = f.req_body && f.req_body.text != null ? f.req_body.text : "";
}

function parseHeaders(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const idx = t.indexOf(":");
    if (idx === -1) continue;
    out.push([t.slice(0, idx).trim(), t.slice(idx + 1).trim()]);
  }
  return out;
}

async function sendRepeater() {
  const btn = $("#rep-send");
  btn.disabled = true;
  btn.textContent = "…";
  try {
    const payload = {
      method: $("#rep-method").value,
      url: $("#rep-url").value.trim(),
      headers: parseHeaders($("#rep-headers").value),
      body_text: $("#rep-body").value || null,
      verify_tls: $("#rep-verify").checked,
      follow_redirects: $("#rep-follow").checked,
    };
    const res = await fetch("/api/repeater/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const f = await res.json();
    if (!res.ok) {
      $("#rep-resp").textContent = "İstek başarısız: " + JSON.stringify(f);
      return;
    }
    if (f.error) {
      $("#rep-resp").textContent = "HATA: " + f.error;
    } else {
      const statusLine = `${f.http_version || "HTTP/1.1"} ${f.status_code ?? ""} ${f.reason ?? ""}`;
      $("#rep-resp").textContent =
        statusLine + "\n" + headersToText(f.resp_headers) + "\n\n" + bodyToText(f.resp_body);
    }
    loadFlows();
  } finally {
    btn.disabled = false;
    btn.textContent = "Gönder";
  }
}

// ---- Sekmeler & olaylar -----------------------------------------------
for (const tab of document.querySelectorAll(".tab")) {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".pane").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("#pane-" + tab.dataset.pane).classList.add("active");
  };
}

$("#refresh").onclick = loadFlows;
$("#search").oninput = debounce(loadFlows, 250);
$("#rep-send").onclick = sendRepeater;
$("#clear").onclick = async () => {
  if (!confirm("Tüm akışlar silinsin mi?")) return;
  await fetch("/api/flows", { method: "DELETE" });
  selectedId = null;
  loadFlows();
};

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// Otomatik yenileme
setInterval(() => { if ($("#autorefresh").checked) loadFlows(); }, 2000);
loadFlows();
