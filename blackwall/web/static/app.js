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

// ---- Intruder ----------------------------------------------------------
const intr = { jobId: null, results: [], poll: null, sort: { key: "index", dir: 1 }, selIdx: null };
const psetCache = [];

function rawFromFlow(f) {
  const line = `${f.method} ${f.path} ${f.http_version || "HTTP/1.1"}`;
  const hdr = f.req_headers.map(([k, v]) => `${k}: ${v}`).join("\n");
  const body = f.req_body && f.req_body.text != null ? f.req_body.text : "";
  return line + "\n" + hdr + "\n\n" + body;
}

function countPositions(text) {
  const m = text.match(/§[^§]*§/g);
  return m ? m.length : 0;
}

function linesOf(text) {
  const arr = (text || "").split("\n");
  if (arr.length && arr[arr.length - 1] === "") arr.pop();
  return arr;
}

function currentAttack() { return $("#intr-attack").value; }

function neededEditors() {
  const pos = countPositions($("#intr-req").value);
  if (currentAttack() === "sniper") return pos > 0 ? 1 : 0;
  return pos;
}

function rebuildPayloadEditors() {
  const container = $("#intr-payloads");
  const n = neededEditors();
  const sniper = currentAttack() === "sniper";
  // mevcut değerleri sakla
  container.querySelectorAll("textarea").forEach((ta) => { psetCache[+ta.dataset.i] = ta.value; });
  container.innerHTML = "";
  if (n === 0) {
    container.innerHTML = `<div class="hint">Önce istekte §...§ ile en az bir konum işaretleyin.</div>`;
    updateEstimate();
    return;
  }
  for (let i = 0; i < n; i++) {
    const label = sniper ? "Tek liste — tüm konumlara uygulanır" : `Konum ${i + 1}`;
    const div = document.createElement("div");
    div.className = "pset";
    div.innerHTML = `
      <div class="pset-head">${label}</div>
      <textarea data-i="${i}" rows="4" spellcheck="false" placeholder="her satır bir payload"></textarea>
      <div class="gen">
        <span class="hint">sayı:</span>
        <input type="number" class="g-from" placeholder="başl" />
        <input type="number" class="g-to" placeholder="bitiş" />
        <input type="number" class="g-step" placeholder="adım" value="1" />
        <button class="mini g-num">ekle</button>
        <span class="hint">karakter seti:</span>
        <input type="text" class="wide g-charset" placeholder="abc0-9 gibi ham" />
        <button class="mini g-char">ekle</button>
        <span class="cnt"></span>
      </div>`;
    const ta = div.querySelector("textarea");
    ta.value = psetCache[i] || "";
    ta.oninput = () => { psetCache[i] = ta.value; updateCount(div, ta); updateEstimate(); };
    div.querySelector(".g-num").onclick = () => {
      const a = parseInt(div.querySelector(".g-from").value, 10);
      const b = parseInt(div.querySelector(".g-to").value, 10);
      let s = parseInt(div.querySelector(".g-step").value, 10) || 1;
      if (Number.isNaN(a) || Number.isNaN(b)) return;
      if (s === 0) s = 1;
      const out = [];
      if (a <= b) for (let v = a; v <= b; v += Math.abs(s)) out.push(v);
      else for (let v = a; v >= b; v -= Math.abs(s)) out.push(v);
      appendLines(ta, out);
    };
    div.querySelector(".g-char").onclick = () => {
      const chars = [...div.querySelector(".g-charset").value];
      appendLines(ta, chars);
    };
    container.appendChild(div);
    updateCount(div, ta);
  }
  updateEstimate();
}

function appendLines(ta, items) {
  if (!items.length) return;
  const cur = ta.value.replace(/\n+$/, "");
  ta.value = (cur ? cur + "\n" : "") + items.join("\n");
  psetCache[+ta.dataset.i] = ta.value;
  const div = ta.closest(".pset");
  updateCount(div, ta);
  updateEstimate();
}

function updateCount(div, ta) {
  div.querySelector(".cnt").textContent = linesOf(ta.value).length + " payload";
}

function getPayloadSets() {
  const tas = [...$("#intr-payloads").querySelectorAll("textarea")];
  return tas.map((ta) => linesOf(ta.value));
}

function updateEstimate() {
  const pos = countPositions($("#intr-req").value);
  $("#intr-poscount").textContent = pos;
  const sets = getPayloadSets();
  let est = 0;
  const attack = currentAttack();
  if (pos > 0 && sets.length) {
    if (attack === "sniper") est = pos * (sets[0] ? sets[0].length : 0);
    else if (attack === "pitchfork") est = sets.length >= pos ? Math.min(...sets.slice(0, pos).map((s) => s.length)) : 0;
    else if (attack === "cluster") est = sets.length >= pos ? sets.slice(0, pos).reduce((a, s) => a * s.length, 1) : 0;
  }
  $("#intr-estimate").textContent = est;
}

$("#intr-load").onclick = () => {
  if (!current) { alert("Önce History'den bir istek seçin."); return; }
  $("#intr-req").value = rawFromFlow(current);
  $("#intr-scheme").value = current.scheme === "http" ? "http" : "https";
  rebuildPayloadEditors();
};

$("#intr-mark").onclick = () => {
  const ta = $("#intr-req");
  const s = ta.selectionStart, e = ta.selectionEnd;
  if (s === e) { alert("Önce istekte işaretlenecek metni seçin."); return; }
  const v = ta.value;
  ta.value = v.slice(0, s) + "§" + v.slice(s, e) + "§" + v.slice(e);
  rebuildPayloadEditors();
};

$("#intr-req").oninput = debounce(rebuildPayloadEditors, 200);
$("#intr-attack").onchange = rebuildPayloadEditors;

async function intruderStart() {
  const pos = countPositions($("#intr-req").value);
  if (pos === 0) { alert("İstekte §...§ ile en az bir konum işaretleyin."); return; }
  const payload = {
    request_text: $("#intr-req").value,
    scheme: $("#intr-scheme").value,
    attack: currentAttack(),
    payload_sets: getPayloadSets(),
    concurrency: parseInt($("#intr-conc").value, 10) || 10,
    timeout: parseFloat($("#intr-timeout").value) || 15,
    verify_tls: $("#intr-verify").checked,
    follow_redirects: $("#intr-follow").checked,
  };
  const res = await fetch("/api/intruder/start", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) { alert("Başlatılamadı: " + (data.detail || JSON.stringify(data))); return; }
  intr.jobId = data.job_id;
  intr.results = [];
  intr.selIdx = null;
  $("#intr-detail").textContent = "";
  $("#intr-start").disabled = true;
  $("#intr-cancel").disabled = false;
  pollIntruder();
}

async function pollIntruder() {
  if (!intr.jobId) return;
  const res = await fetch("/api/intruder/status/" + intr.jobId);
  if (!res.ok) return;
  const data = await res.json();
  intr.results = data.results;
  $("#intr-progress").textContent =
    `${data.state} — ${data.done}/${data.total}`;
  renderIntrTable();
  if (data.state === "running") {
    intr.poll = setTimeout(pollIntruder, 500);
  } else {
    $("#intr-start").disabled = false;
    $("#intr-cancel").disabled = true;
  }
}

$("#intr-start").onclick = intruderStart;
$("#intr-cancel").onclick = async () => {
  if (!intr.jobId) return;
  await fetch("/api/intruder/cancel/" + intr.jobId, { method: "POST" });
};

for (const th of document.querySelectorAll("#intr-table th")) {
  th.onclick = () => {
    const key = th.dataset.sort;
    if (intr.sort.key === key) intr.sort.dir *= -1;
    else intr.sort = { key, dir: 1 };
    renderIntrTable();
  };
}
["#intr-f-status", "#intr-f-min", "#intr-f-max"].forEach((s) => $(s).oninput = debounce(renderIntrTable, 150));
$("#intr-f-err").onchange = renderIntrTable;

function passFilter(r) {
  if ($("#intr-f-err").checked && !r.error) return false;
  const sf = $("#intr-f-status").value.trim();
  if (sf) {
    const prefixes = sf.split(",").map((x) => x.trim()).filter(Boolean);
    const s = r.status != null ? String(r.status) : "";
    if (!prefixes.some((p) => s.startsWith(p))) return false;
  }
  const mn = parseInt($("#intr-f-min").value, 10);
  const mx = parseInt($("#intr-f-max").value, 10);
  if (!Number.isNaN(mn) && (r.length == null || r.length < mn)) return false;
  if (!Number.isNaN(mx) && (r.length == null || r.length > mx)) return false;
  return true;
}

function renderIntrTable() {
  const tbody = $("#intr-tbody");
  const { key, dir } = intr.sort;
  const rows = intr.results.filter(passFilter).slice().sort((a, b) => {
    let x = a[key], y = b[key];
    if (key === "payloads") { x = (x || []).join(","); y = (y || []).join(","); }
    if (x == null) x = key === "error" ? "" : -Infinity;
    if (y == null) y = key === "error" ? "" : -Infinity;
    if (x < y) return -1 * dir;
    if (x > y) return 1 * dir;
    return 0;
  });
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    if (r.index === intr.selIdx) tr.classList.add("sel");
    const pl = (r.payloads || []).join(" | ");
    tr.innerHTML = `
      <td>${r.index}</td>
      <td title="${escapeHtml(pl)}">${escapeHtml(pl)}</td>
      <td class="${r.error ? "s-err" : statusClass(r.status)}">${r.error ? "ERR" : (r.status ?? "—")}</td>
      <td>${r.length ?? "—"}</td>
      <td>${r.duration_ms != null ? Math.round(r.duration_ms) : "—"}</td>
      <td title="${escapeHtml(r.error || "")}">${escapeHtml(r.error || "")}</td>`;
    tr.onclick = () => showIntrDetail(r.index);
    tbody.appendChild(tr);
  }
}

async function showIntrDetail(index) {
  intr.selIdx = index;
  renderIntrTable();
  const res = await fetch(`/api/intruder/result/${intr.jobId}/${index}`);
  if (!res.ok) return;
  const data = await res.json();
  $("#intr-detail-idx").textContent = `#${index}`;
  $("#intr-detail").textContent =
    "=== İSTEK ===\n" + data.request + "\n\n=== YANIT ===\n" + data.response;
}

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
