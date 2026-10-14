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

// ---- Repeater (sekmeli) ------------------------------------------------
const rep = { tabs: [], activeId: null, seq: 0 };

function repFieldsFromDom() {
  return {
    method: $("#rep-method").value,
    url: $("#rep-url").value,
    headers: $("#rep-headers").value,
    body: $("#rep-body").value,
    verify: $("#rep-verify").checked,
    follow: $("#rep-follow").checked,
    resp: $("#rep-resp").textContent,
  };
}

function repFieldsToDom(t) {
  $("#rep-method").value = t.method || "GET";
  $("#rep-url").value = t.url || "";
  $("#rep-headers").value = t.headers || "";
  $("#rep-body").value = t.body || "";
  $("#rep-verify").checked = !!t.verify;
  $("#rep-follow").checked = !!t.follow;
  $("#rep-resp").textContent = t.resp || "";
}

function repActive() { return rep.tabs.find((t) => t.id === rep.activeId) || null; }

function repSaveActive() {
  const a = repActive();
  if (a) Object.assign(a, repFieldsFromDom());
}

function repSwitch(id) {
  repSaveActive();
  rep.activeId = id;
  const t = repActive();
  if (t) repFieldsToDom(t);
  renderRepTabs();
}

function repNewTab(init, name) {
  repSaveActive();
  const id = ++rep.seq;
  const t = Object.assign(
    { id, name: name || `Sekme ${id}`, method: "GET", url: "", headers: "", body: "", verify: false, follow: false, resp: "" },
    init || {},
  );
  rep.tabs.push(t);
  rep.activeId = id;
  repFieldsToDom(t);
  renderRepTabs();
  return t;
}

function repCloseTab(id) {
  const i = rep.tabs.findIndex((t) => t.id === id);
  if (i === -1) return;
  const wasActive = rep.activeId === id;
  rep.tabs.splice(i, 1);
  if (rep.tabs.length === 0) { repNewTab(null, "Sekme"); return; }
  if (wasActive) {
    const next = rep.tabs[Math.max(0, i - 1)];
    rep.activeId = next.id;
    repFieldsToDom(next);
  }
  renderRepTabs();
}

function repRename(id) {
  const t = rep.tabs.find((x) => x.id === id);
  if (!t) return;
  const name = prompt("Sekme adı:", t.name);
  if (name != null && name.trim()) { t.name = name.trim(); renderRepTabs(); }
}

function renderRepTabs() {
  const bar = $("#rep-tabs");
  bar.innerHTML = "";
  for (const t of rep.tabs) {
    const el = document.createElement("div");
    el.className = "rep-tab" + (t.id === rep.activeId ? " active" : "");
    el.title = "çift tıkla: yeniden adlandır";
    const label = document.createElement("span");
    label.textContent = t.name;
    label.onclick = () => repSwitch(t.id);
    el.ondblclick = () => repRename(t.id);
    const x = document.createElement("span");
    x.className = "x"; x.textContent = "×"; x.title = "kapat";
    x.onclick = (e) => { e.stopPropagation(); repCloseTab(t.id); };
    el.appendChild(label); el.appendChild(x);
    bar.appendChild(el);
  }
  const add = document.createElement("button");
  add.className = "rep-tab-add"; add.textContent = "+"; add.title = "yeni sekme";
  add.onclick = () => repNewTab(null);
  bar.appendChild(add);
}

// Bir History/akış kaydından yeni sekme için başlangıç alanları.
function repInitFromFlow(f) {
  let name = "istek";
  try { name = f.method + " " + new URL(f.url).pathname.slice(0, 18); } catch { name = f.method + " " + (f.path || "").slice(0, 18); }
  return {
    name,
    method: f.method,
    url: f.url,
    headers: headersToText(f.req_headers),
    body: f.req_body && f.req_body.text != null ? f.req_body.text : "",
  };
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
    repSaveActive();   // yanıtı aktif sekmede sakla
    loadFlows();
  } finally {
    btn.disabled = false;
    btn.textContent = "Gönder";
  }
}

$("#req-to-repeater").onclick = () => {
  if (!current) { alert("Önce History'den bir istek seçin."); return; }
  repNewTab(repInitFromFlow(current));
  const t = document.querySelector('.tab[data-pane="repeater"]');
  if (t) t.click();
};

// ---- Sekmeler & olaylar -----------------------------------------------
for (const tab of document.querySelectorAll(".tab")) {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".pane").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("#pane-" + tab.dataset.pane).classList.add("active");
    if (tab.dataset.pane === "websocket") { wsLoadFlows(); startWsPolling(); }
    else stopWsPolling();
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
const intr = { jobId: null, results: [], poll: null, sort: { key: "index", dir: 1 }, selIdx: null, grepTerms: [], grepFilter: {} };
const psetCache = [];

function rawFromFlow(f) {
  const line = `${f.method} ${f.path} ${f.http_version || "HTTP/1.1"}`;
  const hdr = f.req_headers.map(([k, v]) => `${k}: ${v}`).join("\n");
  const body = f.req_body && f.req_body.text != null ? f.req_body.text : "";
  return line + "\n" + hdr + "\n\n" + body;
}

// Hedefi flow'un yapısal alanlarından çıkarır (Repeater ile aynı mantık: Host
// başlığına değil, flow'un şema/host/port'una dayanır).
function flowTargetUrl(f) {
  const defPort = (f.scheme === "https" && f.port === 443) || (f.scheme === "http" && f.port === 80);
  const netloc = defPort ? f.host : `${f.host}:${f.port}`;
  return `${f.scheme}://${netloc}`;
}

// Hedef metnini {scheme, host, port}'a ayırır; şema/path/boşluk olsa bile toparlar.
function parseTarget(t) {
  t = (t || "").trim();
  try {
    const u = new URL(t.includes("://") ? t : "http://" + t);
    return {
      scheme: u.protocol.replace(":", "") || "http",
      host: u.hostname,
      port: u.port ? parseInt(u.port, 10) : 0,
    };
  } catch {
    return { scheme: "http", host: t.split("/")[0], port: 0 };
  }
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
  // Hedefi (şema+host+port) flow'dan otomatik al — elle Host/https gerekmez.
  $("#intr-target").value = flowTargetUrl(current);
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
  const tgt = parseTarget($("#intr-target").value);
  if (!tgt.host) { alert("Hedef boş. Önce 'Seçili isteği yükle' ile bir istek alın ya da hedef girin."); return; }
  const payload = {
    request_text: $("#intr-req").value,
    scheme: tgt.scheme,
    host: tgt.host,
    port: tgt.port,
    attack: currentAttack(),
    payload_sets: getPayloadSets(),
    concurrency: parseInt($("#intr-conc").value, 10) || 10,
    timeout: parseFloat($("#intr-timeout").value) || 15,
    verify_tls: $("#intr-verify").checked,
    follow_redirects: $("#intr-follow").checked,
    grep: linesOf($("#intr-grep").value),
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
  ensureGrepUI(data.grep_terms || []);
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

function grepLabel(t) { return t.length > 12 ? t.slice(0, 12) + "…" : t; }

// grep terimlerine göre dinamik sütun başlıkları + filtre açılırları kurar.
function ensureGrepUI(terms) {
  const same = terms.length === intr.grepTerms.length && terms.every((t, i) => t === intr.grepTerms[i]);
  if (same) return;
  intr.grepTerms = terms.slice();
  intr.grepFilter = {};

  const headRow = document.querySelector("#intr-table thead tr");
  headRow.querySelectorAll("th.grep-col").forEach((th) => th.remove());
  terms.forEach((t, i) => {
    const th = document.createElement("th");
    th.className = "grep-col";
    th.dataset.sort = "grep:" + i;
    th.title = t;
    th.textContent = "🔎 " + grepLabel(t);
    th.onclick = () => {
      const key = th.dataset.sort;
      if (intr.sort.key === key) intr.sort.dir *= -1;
      else intr.sort = { key, dir: 1 };
      renderIntrTable();
    };
    headRow.appendChild(th);
  });

  const fc = $("#intr-grep-filters");
  fc.innerHTML = "";
  terms.forEach((t, i) => {
    intr.grepFilter[i] = "all";
    const sel = document.createElement("select");
    sel.className = "grep-filt";
    sel.title = t;
    const lbl = escapeHtml(grepLabel(t));
    sel.innerHTML =
      `<option value="all">${lbl}: hepsi</option>` +
      `<option value="yes">${lbl}: var</option>` +
      `<option value="no">${lbl}: yok</option>`;
    sel.onchange = () => { intr.grepFilter[i] = sel.value; renderIntrTable(); };
    fc.appendChild(sel);
  });
}

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
  // grep sütun filtreleri
  for (const gi in intr.grepFilter) {
    const mode = intr.grepFilter[gi];
    if (mode === "all") continue;
    const has = !!(r.grep && r.grep[gi]);
    if (mode === "yes" && !has) return false;
    if (mode === "no" && has) return false;
  }
  return true;
}

function renderIntrTable() {
  const tbody = $("#intr-tbody");
  const { key, dir } = intr.sort;
  const rows = intr.results.filter(passFilter).slice().sort((a, b) => {
    let x, y;
    if (typeof key === "string" && key.indexOf("grep:") === 0) {
      const gi = +key.slice(5);
      x = (a.grep && a.grep[gi]) ? 1 : 0;
      y = (b.grep && b.grep[gi]) ? 1 : 0;
    } else {
      x = a[key]; y = b[key];
      if (key === "payloads") { x = (x || []).join(","); y = (y || []).join(","); }
      if (x == null) x = key === "error" ? "" : -Infinity;
      if (y == null) y = key === "error" ? "" : -Infinity;
    }
    if (x < y) return -1 * dir;
    if (x > y) return 1 * dir;
    return 0;
  });
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    if (r.index === intr.selIdx) tr.classList.add("sel");
    const pl = (r.payloads || []).join(" | ");
    let grepCells = "";
    for (let i = 0; i < intr.grepTerms.length; i++) {
      const has = !!(r.grep && r.grep[i]);
      grepCells += `<td class="grep-cell ${has ? "g-yes" : "g-no"}" title="${escapeHtml(intr.grepTerms[i])}">${has ? "✓" : "✗"}</td>`;
    }
    tr.innerHTML = `
      <td>${r.index}</td>
      <td title="${escapeHtml(pl)}">${escapeHtml(pl)}</td>
      <td class="${r.error ? "s-err" : statusClass(r.status)}">${r.error ? "ERR" : (r.status ?? "—")}</td>
      <td>${r.length ?? "—"}</td>
      <td>${r.duration_ms != null ? Math.round(r.duration_ms) : "—"}</td>
      <td title="${escapeHtml(r.error || "")}">${escapeHtml(r.error || "")}</td>${grepCells}`;
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

// ---- OAST --------------------------------------------------------------
const oast = { poll: null, selIdx: null, lastCount: 0 };

function setOastButtons(active, polling) {
  $("#oast-start").disabled = active;
  $("#oast-stop").disabled = !active;
  $("#oast-gen").disabled = !active;
  $("#oast-pause").disabled = !active;
  $("#oast-pause").textContent = polling ? "Poll'u duraklat" : "Poll'u sürdür";
  $("#oast-server").disabled = active;
  $("#oast-token").disabled = active;
}

function renderOastUrls(urls) {
  const ul = $("#oast-urls");
  ul.innerHTML = "";
  for (const u of urls) {
    const li = document.createElement("li");
    li.textContent = u;
    li.onclick = () => {
      copyText(u);
      const s = document.createElement("span");
      s.className = "copied"; s.textContent = "✓ kopyalandı";
      li.appendChild(s);
      setTimeout(() => s.remove(), 1200);
    };
    ul.appendChild(li);
  }
}

function renderOastTable(interactions) {
  const tbody = $("#oast-tbody");
  tbody.innerHTML = "";
  // en yeni üstte
  for (const it of [...interactions].reverse()) {
    const tr = document.createElement("tr");
    if (it.index === oast.selIdx) tr.classList.add("sel");
    const t = it.timestamp ? it.timestamp.replace("T", " ").slice(0, 19) : "";
    tr.innerHTML = `
      <td>${it.index}</td>
      <td class="p-${it.protocol}">${it.protocol}</td>
      <td>${it.q_type || "—"}</td>
      <td>${escapeHtml(it.remote_address || "—")}</td>
      <td>${escapeHtml(t)}</td>
      <td title="${escapeHtml(it.full_id)}">${escapeHtml(it.full_id)}</td>`;
    tr.onclick = () => showOastDetail(it.index);
    tbody.appendChild(tr);
  }
}

function applyOastStatus(data) {
  setOastButtons(data.active, data.polling);
  renderOastUrls(data.urls || []);
  renderOastTable(data.interactions || []);
  $("#oast-count").textContent = data.count || 0;
  let state = data.active ? (data.polling ? "dinleniyor" : "duraklatıldı") : "kapalı";
  if (data.correlation_id) state += ` · id ${data.correlation_id} · ${data.server}`;
  if (data.error) state += ` · ⚠ ${data.error}`;
  $("#oast-state").textContent = state;
  oast.lastCount = data.count || 0;
}

async function oastStatus() {
  const res = await fetch("/api/oast/status");
  if (res.ok) applyOastStatus(await res.json());
}

$("#oast-start").onclick = async () => {
  $("#oast-start").disabled = true;
  $("#oast-state").textContent = "kaydolunuyor…";
  const res = await fetch("/api/oast/start", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ server: $("#oast-server").value.trim(), token: $("#oast-token").value.trim() }),
  });
  const data = await res.json();
  if (!res.ok) { $("#oast-state").textContent = "⚠ " + (data.detail || "başlatılamadı"); $("#oast-start").disabled = false; return; }
  oast.selIdx = null; $("#oast-detail").textContent = "";
  applyOastStatus(data);
  startOastPolling();
};

$("#oast-stop").onclick = async () => {
  stopOastPolling();
  await fetch("/api/oast/stop", { method: "POST" });
  oastStatus();
};

$("#oast-gen").onclick = async () => {
  const res = await fetch("/api/oast/generate", { method: "POST" });
  const data = await res.json();
  if (res.ok) { copyText(data.url); oastStatus(); }
};

$("#oast-pause").onclick = async () => {
  const polling = $("#oast-pause").textContent.includes("duraklat");
  await fetch("/api/oast/" + (polling ? "pause" : "resume"), { method: "POST" });
  oastStatus();
};

function startOastPolling() {
  stopOastPolling();
  oast.poll = setInterval(oastStatus, 3000);
}
function stopOastPolling() {
  if (oast.poll) { clearInterval(oast.poll); oast.poll = null; }
}

async function showOastDetail(index) {
  oast.selIdx = index;
  const res = await fetch("/api/oast/interaction/" + index);
  if (!res.ok) return;
  const d = await res.json();
  $("#oast-detail-idx").textContent = `#${index} · ${d.protocol}`;
  let out = `protokol : ${d.protocol}\n`;
  if (d.q_type) out += `tip      : ${d.q_type}\n`;
  out += `kaynak IP: ${d.remote_address}\nzaman    : ${d.timestamp}\nfull-id  : ${d.full_id}\n`;
  out += `\n=== HAM İSTEK ===\n${d.raw_request || "(yok)"}`;
  if (d.raw_response) out += `\n\n=== HAM YANIT ===\n${d.raw_response}`;
  $("#oast-detail").textContent = out;
  for (const tr of $("#oast-tbody").querySelectorAll("tr")) {
    tr.classList.toggle("sel", tr.firstElementChild && tr.firstElementChild.textContent === String(index));
  }
}

// ---- Raw ---------------------------------------------------------------
const RAW_HINTS = {
  crlf: "Her satır \\r\\n ile biter. Textarea'da yazılan normal istekler için.",
  lf: "Satır sonları LF (\\n) kalır — bare-LF testleri için.",
  escape: "Gerçek satır sonları yok sayılır; byte'ları \\r \\n \\t \\0 \\xHH ile yazın. Tam kontrol.",
};
function rawHint() { $("#raw-mode-hint").textContent = RAW_HINTS[$("#raw-mode").value]; }
$("#raw-mode").onchange = rawHint;

function b64ToBytes(b64) {
  const bin = atob(b64 || "");
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function bytesToLatin1(arr) {
  let s = "";
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return s;
}
function bytesToHex(arr) {
  let out = "";
  for (let off = 0; off < arr.length; off += 16) {
    const slice = arr.subarray(off, off + 16);
    const hex = [...slice].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = [...slice].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    out += off.toString(16).padStart(8, "0") + "  " + hex.padEnd(16 * 3 - 1) + "  " + asc + "\n";
  }
  return out;
}
function renderBytes(b64) {
  const arr = b64ToBytes(b64);
  return $("#raw-hex").checked ? bytesToHex(arr) : bytesToLatin1(arr);
}

async function rawSend() {
  const btn = $("#raw-send");
  btn.disabled = true; $("#raw-state").textContent = "gönderiliyor…";
  const payload = {
    host: $("#raw-host").value.trim(),
    port: parseInt($("#raw-port").value, 10) || 80,
    tls: $("#raw-tls").checked,
    mode: $("#raw-mode").value,
    request1: $("#raw-req1").value,
    request2: $("#raw-req2").value,
    timeout: parseFloat($("#raw-timeout").value) || 10,
    read_idle: parseFloat($("#raw-idle").value) || 1,
    delay_ms: parseInt($("#raw-delay").value, 10) || 0,
    sni: $("#raw-sni").value.trim() || null,
  };
  try {
    const res = await fetch("/api/raw/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) { $("#raw-state").textContent = "⚠ " + (data.detail || "hata"); return; }
    renderRawResult(data);
    $("#raw-state").textContent = data.error ? "⚠ " + data.error
      : `bağlantı OK${data.tls_version ? " · " + data.tls_version : ""} · ${data.requests.length} istek`;
  } finally {
    btn.disabled = false;
  }
}

let lastRawData = null;
function renderRawResult(data) {
  lastRawData = data;
  const box = $("#raw-results");
  box.innerHTML = "";
  if (data.error) {
    const d = document.createElement("div");
    d.className = "raw-result"; d.innerHTML = `<div class="rhead err">${escapeHtml(data.error)}</div>`;
    box.appendChild(d);
  }
  for (const r of data.requests) {
    const div = document.createElement("div");
    div.className = "raw-result";
    let head = `<span>istek #${r.index + 1}</span><span>gönderilen: ${r.sent_size} B</span>` +
      `<span>yanıt: ${r.response_size} B</span><span>${Math.round(r.duration_ms)} ms</span>`;
    if (r.send_error) head += `<span class="err">gönderme: ${escapeHtml(r.send_error)}</span>`;
    if (r.recv_error) head += `<span class="err">okuma: ${escapeHtml(r.recv_error)}</span>`;
    const pre = document.createElement("pre");
    pre.textContent = renderBytes(r.response_base64);
    const sent = document.createElement("details");
    sent.innerHTML = `<summary>gönderilen ham byte'lar (${r.sent_size} B)</summary>`;
    const spre = document.createElement("pre");
    spre.className = "sent";
    spre.textContent = renderBytes(r.sent_base64);
    sent.appendChild(spre);
    const h = document.createElement("div"); h.className = "rhead"; h.innerHTML = head;
    div.appendChild(h); div.appendChild(pre); div.appendChild(sent);
    box.appendChild(div);
  }
}

$("#raw-send").onclick = rawSend;
$("#raw-hex").onchange = () => { if (lastRawData) renderRawResult(lastRawData); };
rawHint();

// ---- Race --------------------------------------------------------------
let lastRaceData = null;
const raceSel = { idx: null };

// Seçili History/Repeater isteğini yükle: tüm header'lar + body birebir,
// request line HTTP/1.1; hedef host/port/şema flow'dan (Host satırına güvenme).
$("#race-load").onclick = () => {
  if (!current) { alert("Önce History'den bir istek seçin."); return; }
  const line = `${current.method} ${current.path} HTTP/1.1`;
  const hdr = current.req_headers.map(([k, v]) => `${k}: ${v}`).join("\n");
  const body = current.req_body && current.req_body.text != null ? current.req_body.text : "";
  $("#race-req").value = line + "\n" + hdr + "\n\n" + body;
  $("#race-host").value = current.host;
  $("#race-port").value = current.port;
  $("#race-tls").checked = current.scheme === "https";
  $("#race-sni").value = "";
};

async function raceRun() {
  const btn = $("#race-run");
  btn.disabled = true; $("#race-state").textContent = "saldırı sürüyor…";
  const payload = {
    host: $("#race-host").value.trim(),
    port: parseInt($("#race-port").value, 10) || (($("#race-tls").checked) ? 443 : 80),
    tls: $("#race-tls").checked,
    sync_mode: $("#race-sync").value,
    request: $("#race-req").value,
    count: parseInt($("#race-count").value, 10) || 20,
    timeout: parseFloat($("#race-timeout").value) || 10,
    read_idle: parseFloat($("#race-idle").value) || 1,
    prefix_delay_ms: parseInt($("#race-prefix").value, 10) || 0,
    sni: $("#race-sni").value.trim() || null,
  };
  try {
    const res = await fetch("/api/race/run", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) { $("#race-state").textContent = "⚠ " + (data.detail || "hata"); return; }
    lastRaceData = data;
    renderRaceTable(data);
    const distinct = data.results.filter((r) => r.distinct).length;
    $("#race-state").textContent =
      (data.error ? "⚠ " + data.error + " · " : "") +
      `${data.count} bağlantı · çoğunluk ${data.majority || "—"} · ` +
      `sync ±${data.sync_spread_ms.toFixed(2)}ms · farklı: ${distinct}`;
  } finally {
    btn.disabled = false;
  }
}

function renderRaceTable(data) {
  const tbody = $("#race-tbody");
  tbody.innerHTML = "";
  for (const r of data.results) {
    const tr = document.createElement("tr");
    if (r.distinct) tr.classList.add("distinct");
    if (r.index === raceSel.idx) tr.classList.add("sel");
    tr.innerHTML = `
      <td>${r.index}</td>
      <td class="${r.error ? "s-err" : statusClass(r.status)}">${r.error ? "ERR" : (r.status ?? "—")}</td>
      <td>${r.response_size}</td>
      <td>${r.sent_offset_ms != null ? r.sent_offset_ms.toFixed(1) : "—"}</td>
      <td>${r.arrival_ms != null ? r.arrival_ms.toFixed(1) : "—"}</td>
      <td>${r.distinct ? "★ " : ""}${escapeHtml(r.signature)}</td>
      <td title="${escapeHtml(r.error || "")}">${escapeHtml(r.error || "")}</td>`;
    tr.onclick = () => showRaceDetail(r.index);
    tbody.appendChild(tr);
  }
}

function showRaceDetail(index) {
  raceSel.idx = index;
  const r = lastRaceData.results.find((x) => x.index === index);
  if (!r) return;
  $("#race-detail-idx").textContent =
    `#${index} · ${r.signature}` + (r.distinct ? " · ★ farklı sonuç" : "");
  const resp = r.response_base64
    ? bytesToLatin1(b64ToBytes(r.response_base64))
    : (r.error ? "HATA: " + r.error : "(yanıt yok)");
  const hex = $("#race-hex").checked;
  const sent = lastRaceData
    ? (hex ? (lastRaceData.sent_request_hex || "") : (lastRaceData.sent_request || ""))
    : "(yok)";
  const label = hex ? "GÖNDERİLEN İSTEK (hex, tüm bağlantılarda aynı)"
                    : "GÖNDERİLEN İSTEK (tüm bağlantılarda aynı)";
  $("#race-detail").textContent =
    "=== " + label + " ===\n" + sent + "\n\n=== YANIT ===\n" + resp;
  for (const tr of $("#race-tbody").querySelectorAll("tr")) {
    tr.classList.toggle("sel", tr.firstElementChild && tr.firstElementChild.textContent === String(index));
  }
}

$("#race-run").onclick = raceRun;
$("#race-hex").onchange = () => { if (raceSel.idx != null) showRaceDetail(raceSel.idx); };
$("#race-sync").onchange = () => {
  const sp = $("#race-sync").value === "single-packet";
  if (sp) { $("#race-tls").checked = true; }   // h2 ALPN → TLS zorunlu
  $("#race-tls").disabled = sp;
  $("#race-state").textContent = sp
    ? "single-packet: tek TLS bağlantısı (h2), tüm END_STREAM frame'leri tek pakette"
    : "";
};

// ---- WebSocket ---------------------------------------------------------
const ws = { flowId: null, state: null, lastId: 0, poll: null };

async function wsLoadFlows() {
  const res = await fetch("/api/ws/flows");
  if (!res.ok) return;
  const data = await res.json();
  const ul = $("#ws-conn-list");
  ul.innerHTML = "";
  if (!data.flows.length) {
    ul.innerHTML = `<li class="hint" style="cursor:default;border:none">Henüz WebSocket bağlantısı yakalanmadı.</li>`;
  }
  for (const f of data.flows) {
    const li = document.createElement("li");
    if (f.flow_id === ws.flowId) li.classList.add("sel");
    const when = new Date(f.created_at * 1000).toLocaleTimeString();
    li.innerHTML = `
      <div class="host">${escapeHtml(f.host)}:${f.port}${escapeHtml(f.path)}</div>
      <div class="meta">
        <span class="ws-state-${f.state}">●</span> ${f.state} ·
        ${f.msg_count} mesaj · ${when}
      </div>`;
    li.onclick = () => wsSelect(f.flow_id, f.state);
    ul.appendChild(li);
  }
}

function wsSelect(flowId, state) {
  const changed = flowId !== ws.flowId;
  ws.flowId = flowId;
  ws.state = state;
  if (changed) { ws.lastId = 0; $("#ws-messages").innerHTML = ""; }
  $("#ws-send").disabled = state !== "open";
  $("#ws-msg-head").textContent =
    `${flowId.slice(0, 8)}… · ${state}` + (state === "open" ? " · enjeksiyon aktif" : " · bağlantı kapalı");
  wsLoadFlows();
  wsLoadMessages(true);
}

async function wsLoadMessages(reset) {
  if (!ws.flowId) return;
  if (reset) { ws.lastId = 0; $("#ws-messages").innerHTML = ""; }
  const res = await fetch(`/api/ws/flows/${ws.flowId}/messages?after_id=${ws.lastId}`);
  if (!res.ok) return;
  const data = await res.json();
  const box = $("#ws-messages");
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  for (const m of data.messages) {
    ws.lastId = Math.max(ws.lastId, m.id);
    const div = document.createElement("div");
    div.className = "ws-msg " + m.direction + (m.injected ? " injected" : "");
    const arrow = m.direction === "c2s" ? "▲" : "▼";
    const when = new Date(m.created_at * 1000).toLocaleTimeString();
    const body = m.type === "text" && m.content.text != null
      ? m.content.text
      : `[${m.type}, ${m.content.size} bayt] ${m.content.base64 || ""}`;
    div.innerHTML = `<span class="dir">${arrow}</span>${escapeHtml(body)}` +
      `<span class="t">${when}</span>` + (m.injected ? `<span class="inj">⟵ enjekte</span>` : "");
    box.appendChild(div);
  }
  if (atBottom) box.scrollTop = box.scrollHeight;
}

$("#ws-refresh").onclick = wsLoadFlows;

$("#ws-send").onclick = async () => {
  if (!ws.flowId) return;
  const type = $("#ws-type").value;
  const payload = { flow_id: ws.flowId, direction: $("#ws-dir").value, type };
  const body = $("#ws-inject-body").value;
  if (type === "binary") payload.content_base64 = body.trim();
  else payload.content_text = body;
  $("#ws-inject-state").textContent = "gönderiliyor…";
  const res = await fetch("/api/ws/inject", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) { $("#ws-inject-state").textContent = "⚠ " + (data.detail || "hata"); return; }
  // enjeksiyon durumunu yokla
  const id = data.inject_id;
  let tries = 0;
  const check = async () => {
    const r = await fetch("/api/ws/inject/" + id);
    const s = await r.json();
    if (s.status === "pending" && tries++ < 15) { setTimeout(check, 300); return; }
    const map = { done: "✓ gönderildi", gone: "⚠ bağlantı kapalı", error: "⚠ " + (s.error || "hata"), pending: "zaman aşımı" };
    $("#ws-inject-state").textContent = map[s.status] || s.status;
    wsLoadMessages(false);
  };
  check();
  $("#ws-inject-body").value = "";
};

function startWsPolling() {
  stopWsPolling();
  ws.poll = setInterval(() => { wsLoadFlows(); wsLoadMessages(false); }, 1500);
}
function stopWsPolling() { if (ws.poll) { clearInterval(ws.poll); ws.poll = null; } }

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

// Açılışta aktif OAST oturumu varsa yükle ve pollingi sürdür
oastStatus().then(() => { if ($("#oast-stop").disabled === false) startOastPolling(); });

// Repeater: açılışta bir boş sekme
repNewTab(null);
