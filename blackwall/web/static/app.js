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
  renderInspector(current);
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

// ---- Inspector ---------------------------------------------------------
function findHeader(headers, name) {
  const low = name.toLowerCase();
  return headers.filter(([k]) => k.toLowerCase() === low).map(([, v]) => v);
}

function kvRows(tbodySel, pairs) {
  const tbody = document.querySelector(tbodySel + " tbody");
  tbody.innerHTML = "";
  if (!pairs.length) {
    tbody.innerHTML = `<tr><td class="empty" colspan="2">—</td></tr>`;
    return;
  }
  for (const [k, v] of pairs) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="k">${escapeHtml(k)}</td><td>${escapeHtml(v)}</td>`;
    tbody.appendChild(tr);
  }
}

function parseQuery(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()];
  } catch { return []; }
}

function parseCookies(headers) {
  const out = [];
  for (const raw of findHeader(headers, "cookie")) {
    for (const part of raw.split(";")) {
      const t = part.trim();
      if (!t) continue;
      const idx = t.indexOf("=");
      if (idx === -1) out.push([t, ""]);
      else out.push([t.slice(0, idx).trim(), t.slice(idx + 1).trim()]);
    }
  }
  return out;
}

function renderInspector(f) {
  const empty = $("#insp-empty"), content = $("#insp-content");
  if (!f) { empty.hidden = false; content.hidden = true; return; }
  empty.hidden = true; content.hidden = false;
  $("#insp-line").textContent = `${f.method} ${f.url}`;
  kvRows("#insp-query", parseQuery(f.url));
  kvRows("#insp-cookies", parseCookies(f.req_headers));
  kvRows("#insp-headers", f.req_headers);
}

// ---- Decoder -----------------------------------------------------------
let decPipeline = [];

function renderPipeline(steps) {
  const ol = $("#dec-pipeline");
  ol.innerHTML = "";
  decPipeline.forEach((op, i) => {
    const step = steps && steps[i];
    const li = document.createElement("li");
    const out = step ? (step.error ? step.error : step.output) : "";
    li.innerHTML = `
      <span class="idx">${i + 1}.</span>
      <span class="op">${op}</span>
      <span class="out ${step && step.error ? "err" : ""}" title="${escapeHtml(out)}">${escapeHtml(truncate(out, 120))}</span>
      <button data-i="${i}">✕</button>`;
    li.querySelector("button").onclick = () => { decPipeline.splice(i, 1); runDecoder(); };
    ol.appendChild(li);
  });
}

function truncate(s, n) { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; }

async function runDecoder() {
  const res = await fetch("/api/decoder/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input: $("#dec-input").value, ops: decPipeline }),
  });
  const data = await res.json();
  renderPipeline(data.steps);
  const last = data.steps[data.steps.length - 1];
  $("#dec-result").textContent =
    data.result != null ? data.result : (last && last.error ? "HATA: " + last.error : "");
}

$("#dec-add").onclick = () => { decPipeline.push($("#dec-op").value); runDecoder(); };
$("#dec-clear").onclick = () => { decPipeline = []; runDecoder(); };
$("#dec-input").oninput = debounce(runDecoder, 200);
$("#dec-copy").onclick = () => copyText($("#dec-result").textContent);

// ---- JWT ---------------------------------------------------------------
async function jwtDecode() {
  const token = $("#jwt-token").value.trim();
  if (!token) return;
  const res = await fetch("/api/jwt/decode", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  const data = await res.json();
  if (!res.ok) { $("#jwt-out").textContent = "HATA: " + (data.detail || JSON.stringify(data)); return; }
  $("#jwt-header").value = pretty(data.header);
  $("#jwt-payload").value = pretty(data.payload);
  $("#jwt-out").textContent =
    `alg: ${data.alg}\nbölüm sayısı: ${data.parts}\nimza (b64url): ${data.signature || "(yok)"}`;
}

function pretty(v) {
  if (typeof v === "string") return v;
  try { return JSON.stringify(v, null, 2); } catch { return String(v); }
}

function parseJsonField(sel, label) {
  const txt = $(sel).value.trim();
  try { return JSON.parse(txt); }
  catch (e) { throw new Error(`${label} geçerli JSON değil: ${e.message}`); }
}

async function jwtSign(alg) {
  try {
    const payload = parseJsonField("#jwt-payload", "Payload");
    let header = {};
    try { header = parseJsonField("#jwt-header", "Header"); } catch { header = {}; }
    const res = await fetch("/api/jwt/sign", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload, alg, secret: $("#jwt-secret").value, header }),
    });
    const data = await res.json();
    if (!res.ok) { $("#jwt-out").textContent = "HATA: " + (data.detail || JSON.stringify(data)); return; }
    $("#jwt-out").textContent = data.token;
    $("#jwt-token").value = data.token;
  } catch (e) {
    $("#jwt-out").textContent = "HATA: " + e.message;
  }
}

$("#jwt-decode").onclick = jwtDecode;
$("#jwt-none").onclick = () => jwtSign("none");
$("#jwt-hs256").onclick = () => jwtSign("HS256");
$("#jwt-copy").onclick = () => copyText($("#jwt-out").textContent);

// ---- Kopyalama ---------------------------------------------------------
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Güvenli bağlam değilse fallback
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch {}
    ta.remove();
  }
}

// Otomatik yenileme
setInterval(() => { if ($("#autorefresh").checked) loadFlows(); }, 2000);
loadFlows();
