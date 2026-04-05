#!/usr/bin/env node
// Usage: node encrypt.js <password> <input.html> <output.html>
const crypto = require('crypto');
const fs = require('fs');

const password = process.argv[2];
const inputFile = process.argv[3];
const outputFile = process.argv[4];

if (!password || !inputFile || !outputFile) {
  console.error('Usage: node encrypt.js <password> <input.html> <output.html>');
  process.exit(1);
}

const plaintext = fs.readFileSync(inputFile, 'utf8');

// Encrypt with AES-256-GCM
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(plaintext, 'utf8', 'base64');
encrypted += cipher.final('base64');
const tag = cipher.getAuthTag().toString('base64');

const payload = JSON.stringify({
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  tag: tag,
  data: encrypted
});

const shell = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Travel Plan</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Noto+Sans+SC:wght@300;400;500&display=swap');
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'Noto Sans SC', sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .lock-screen {
    text-align: center;
    padding: 2rem;
    max-width: 400px;
    width: 100%;
  }
  .lock-icon {
    font-size: 3rem;
    margin-bottom: 1.5rem;
    animation: float 3s ease-in-out infinite;
  }
  @keyframes float {
    0%,100% { transform: translateY(0); }
    50% { transform: translateY(-8px); }
  }
  .lock-title {
    font-family: 'Playfair Display', serif;
    font-size: 1.8rem;
    color: #fff;
    margin-bottom: 0.5rem;
  }
  .lock-subtitle {
    color: rgba(255,255,255,0.5);
    font-size: 0.9rem;
    margin-bottom: 2rem;
    font-weight: 300;
  }
  .input-group {
    position: relative;
    margin-bottom: 1rem;
  }
  .input-group input {
    width: 100%;
    padding: 14px 20px;
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 12px;
    background: rgba(255,255,255,0.08);
    color: #fff;
    font-size: 1rem;
    outline: none;
    transition: border-color 0.3s;
    font-family: 'Noto Sans SC', sans-serif;
  }
  .input-group input::placeholder { color: rgba(255,255,255,0.3); }
  .input-group input:focus { border-color: #C9A96E; }
  .unlock-btn {
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 12px;
    background: linear-gradient(135deg, #C9A96E, #e8c57d);
    color: #1a1a2e;
    font-size: 1rem;
    font-weight: 700;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    font-family: 'Noto Sans SC', sans-serif;
  }
  .unlock-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(201,169,110,0.3);
  }
  .unlock-btn:active { transform: translateY(0); }
  .error-msg {
    color: #ef4444;
    font-size: 0.85rem;
    margin-top: 0.8rem;
    opacity: 0;
    transition: opacity 0.3s;
  }
  .error-msg.show { opacity: 1; }
  .hint {
    color: rgba(255,255,255,0.25);
    font-size: 0.75rem;
    margin-top: 2rem;
  }
</style>
</head>
<body>
<div class="lock-screen" id="lockScreen">
  <div class="lock-icon">🔐</div>
  <div class="lock-title">Private Trip</div>
  <div class="lock-subtitle">Roma · Vaticano · Toscana · Nice</div>
  <div class="input-group">
    <input type="password" id="pwdInput" placeholder="Enter password" autofocus
      onkeydown="if(event.key==='Enter')unlock()"/>
  </div>
  <button class="unlock-btn" onclick="unlock()">Unlock</button>
  <div class="error-msg" id="errorMsg">Password incorrect</div>
  <div class="hint">AES-256-GCM Encrypted</div>
</div>

<script>
const PAYLOAD = ${payload};

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

function b64toArr(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function doDecrypt(pwd) {
  const salt = b64toArr(PAYLOAD.salt);
  const iv = b64toArr(PAYLOAD.iv);
  const tag = b64toArr(PAYLOAD.tag);
  const data = b64toArr(PAYLOAD.data);
  const combined = new Uint8Array(data.length + tag.length);
  combined.set(data);
  combined.set(tag, data.length);
  const key = await deriveKey(pwd, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv }, key, combined
  );
  return new TextDecoder().decode(decrypted);
}

function showPage(html) {
  document.open();
  document.write(html);
  document.close();
}

async function unlock() {
  const pwd = document.getElementById('pwdInput').value;
  if (!pwd) return;
  try {
    const html = await doDecrypt(pwd);
    // Save password to localStorage so next visit auto-unlocks
    localStorage.setItem('_trip_pwd', pwd);
    showPage(html);
  } catch (e) {
    const err = document.getElementById('errorMsg');
    err.classList.add('show');
    document.getElementById('pwdInput').value = '';
    document.getElementById('pwdInput').focus();
    setTimeout(() => err.classList.remove('show'), 2000);
  }
}

// Auto-unlock if previously authenticated on this device
(async function autoUnlock() {
  const saved = localStorage.getItem('_trip_pwd');
  if (!saved) return;
  try {
    const html = await doDecrypt(saved);
    showPage(html);
  } catch (e) {
    // Password changed or data updated, clear saved password
    localStorage.removeItem('_trip_pwd');
  }
})();
</script>
</body>
</html>`;

fs.writeFileSync(outputFile, shell, 'utf8');
console.log('Encrypted successfully! Output: ' + outputFile);
