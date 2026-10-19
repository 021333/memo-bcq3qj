// 自転車番号検索: 暗号化データ(data.enc.json)をブラウザ内で1件ずつ復号する。
// 鍵は共有リンクの「#k=」以降にだけあり、サーバーには送られない。方式は tools/build_data.py と対応。
"use strict";

const IDLE_CLEAR_MS = 3 * 60 * 1000;
const HINT = "4桁の番号を入力すると生徒名を表示します";
const enc = new TextEncoder();
const dec = new TextDecoder();

const $ = (id) => document.getElementById(id);
const els = {
  statusView: $("status-view"),
  status: $("status"),
  searchView: $("search-view"),
  searchForm: $("search-form"),
  num: $("num"),
  result: $("result"),
};

let blob = null;
let keys = null; // { mac: CryptoKey, aes: CryptoKey }
let idleTimer = null;

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

function linkKey() {
  return new URLSearchParams(location.hash.slice(1)).get("k");
}

async function loadBlob() {
  if (blob) return blob;
  const res = await fetch("data.enc.json", { cache: "no-store" });
  if (!res.ok) throw new Error("data");
  blob = await res.json();
  return blob;
}

async function deriveKeys(secret, kdf) {
  const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: kdf.hash, salt: b64(kdf.salt), iterations: kdf.iterations }, base, 512));
  const mac = await crypto.subtle.importKey("raw", bits.slice(0, 32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const aes = await crypto.subtle.importKey("raw", bits.slice(32), "AES-GCM", false, ["decrypt"]);
  bits.fill(0);
  return { mac, aes };
}

async function unseal(aes, sealed, aad) {
  const raw = b64(sealed);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: raw.slice(0, 12), additionalData: enc.encode(aad) }, aes, raw.slice(12));
  return dec.decode(plain).replace(/\u0000+$/, "");
}

async function lookup(num) {
  const id = hex(await crypto.subtle.sign("HMAC", keys.mac, enc.encode("n:" + num)));
  const sealed = blob.entries[id];
  return sealed ? unseal(keys.aes, sealed, id) : null;
}

function normalize(s) {
  return s.replace(/[０-９]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0)).replace(/\D/g, "").slice(0, 4);
}

function show(kind, num, text) {
  els.result.replaceChildren();
  if (kind === "hint") {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = text;
    els.result.append(p);
    return;
  }
  const box = document.createElement("div");
  box.className = "box " + kind;
  const label = document.createElement("div");
  label.className = "label";
  label.textContent = "番号 " + num;
  const name = document.createElement("div");
  name.className = "name" + (text.length > 10 ? " long" : "");
  name.textContent = text;
  box.append(label, name);
  els.result.append(box);
}

// しばらく操作がなければ表示中の名前を消す
function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    els.num.value = "";
    show("hint", "", HINT);
  }, IDLE_CLEAR_MS);
}

let seq = 0;
async function onInput() {
  const v = normalize(els.num.value);
  if (v !== els.num.value) els.num.value = v;
  resetIdle();
  if (v.length < 4) {
    show("hint", "", HINT);
    return;
  }
  const mine = ++seq;
  const name = await lookup(v);
  if (mine !== seq) return; // 入力が進んでいたら古い結果は捨てる
  if (name) show("hit", v, name);
  else show("miss", v, "登録されていない番号です");
}

function fail(message) {
  keys = null;
  els.searchView.hidden = true;
  els.statusView.hidden = false;
  els.status.textContent = message;
}

async function start() {
  if (!window.crypto || !crypto.subtle) {
    fail("このブラウザでは使えません（https で開いてください）");
    return;
  }
  const secret = linkKey();
  if (!secret) {
    fail("職員用に共有されたリンクから開いてください。");
    return;
  }
  try {
    const data = await loadBlob();
    const k = await deriveKeys(secret, data.kdf);
    await unseal(k.aes, data.check, "check").catch(() => { throw new Error("key"); });
    keys = k;
  } catch (e) {
    fail(e.message === "key"
      ? "リンクが正しくないか、古いリンクです。最新のリンクを管理者に確認してください。"
      : "データを読み込めませんでした。通信状況を確認してください。");
    return;
  }
  els.statusView.hidden = true;
  els.searchView.hidden = false;
  show("hint", "", HINT);
  els.num.focus();
}

els.num.addEventListener("input", onInput);
els.searchForm.addEventListener("submit", (e) => { e.preventDefault(); onInput(); });
els.num.addEventListener("focus", () => els.num.select());
window.addEventListener("hashchange", start);

start();
