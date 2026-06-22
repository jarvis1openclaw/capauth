/**
 * CapAuth options page controller.
 *
 * Manages persistent settings in chrome.storage.local, including the
 * configurable signer-backend (key custody):
 *   - local-plaintext: armored key stored UNENCRYPTED (testing).
 *   - local-encrypted: armored key encrypted at rest (PBKDF2 → AES-GCM).
 *   - native-gpg:      key never enters the browser; signs via gpg-agent host.
 *   - remote:          key lives on a paired PHONE (CapAuth Bunker); the phone
 *                      signs over a relay. Pairing state is stored here.
 *
 * @module options
 */

import { encryptPrivateKey, isEncryptedEnvelope } from "../lib/keyvault.js";

const SETTINGS_KEY = "capauth_settings";
const TOKEN_STORAGE_PREFIX = "capauth_token_";

const BACKENDS = {
  PLAINTEXT: "local-plaintext",
  ENCRYPTED: "local-encrypted",
  NATIVE: "native-gpg",
  REMOTE: "remote",
};

const DEFAULTS = {
  fingerprint: "",
  serviceUrl: "",
  privateKeyArmored: "",
  publicKeyArmored: "",
  encryptedKey: null,
  signerBackend: BACKENDS.PLAINTEXT,
  autoSign: false,
  // Remote signer (CapAuth Bunker) pairing state.
  bunkerBaseUrl: "",
  bunkerPairing: null, // { sessionId, pairingSecret, relayWsUrl }
};

let currentSettings = { ...DEFAULTS };

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function selectedBackend() {
  const checked = document.querySelector('input[name="signer-backend"]:checked');
  return checked ? checked.value : BACKENDS.PLAINTEXT;
}

function setBackendRadio(value) {
  const el = document.querySelector(`input[name="signer-backend"][value="${value}"]`);
  if (el) el.checked = true;
}

/** Show only the panel for the active backend + refresh dependent UI. */
function syncBackendPanels() {
  const backend = selectedBackend();
  $("backend-local-plaintext").style.display = backend === BACKENDS.PLAINTEXT ? "block" : "none";
  $("backend-local-encrypted").style.display = backend === BACKENDS.ENCRYPTED ? "block" : "none";
  $("backend-native-gpg").style.display = backend === BACKENDS.NATIVE ? "block" : "none";
  $("backend-remote").style.display = backend === BACKENDS.REMOTE ? "block" : "none";

  // Migration prompt: offer to encrypt an existing plaintext key.
  if (backend === BACKENDS.ENCRYPTED) {
    const hasLegacyPlaintext = !!currentSettings.privateKeyArmored;
    $("migrate-box").style.display = hasLegacyPlaintext ? "block" : "none";
    const encStatus = $("enc-status");
    if (isEncryptedEnvelope(currentSettings.encryptedKey)) {
      encStatus.textContent = "An encrypted key is already stored. Re-paste + set a passphrase to replace it.";
    } else {
      encStatus.textContent = "";
    }
  }
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

async function loadSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  currentSettings = { ...DEFAULTS, ...result[SETTINGS_KEY] };

  $("fingerprint").value = currentSettings.fingerprint;
  $("service-url").value = currentSettings.serviceUrl;
  $("private-key").value = currentSettings.privateKeyArmored;
  $("public-key").value = currentSettings.publicKeyArmored;
  $("auto-sign").checked = currentSettings.autoSign;
  $("native-fingerprint").value = currentSettings.fingerprint;
  $("remote-fingerprint").value = currentSettings.fingerprint;
  $("bunker-base-url").value = currentSettings.bunkerBaseUrl || "";
  if (currentSettings.bunkerPairing && currentSettings.bunkerPairing.sessionId) {
    $("bunker-status").textContent =
      "Paired session: " + currentSettings.bunkerPairing.sessionId;
  }

  setBackendRadio(currentSettings.signerBackend || BACKENDS.PLAINTEXT);
  syncBackendPanels();
}

function validateFingerprint(fp) {
  if (!fp) return true;
  if (fp.length !== 40) {
    showStatus("Fingerprint must be exactly 40 hex characters", true);
    return false;
  }
  if (!/^[A-F0-9]{40}$/.test(fp)) {
    showStatus("Fingerprint must contain only hex characters (0-9, A-F)", true);
    return false;
  }
  return true;
}

async function saveSettings() {
  const backend = selectedBackend();
  const serviceUrl = $("service-url").value.trim();
  const publicKeyArmored = $("public-key").value.trim();
  const autoSign = $("auto-sign").checked;

  if (publicKeyArmored && !publicKeyArmored.includes("BEGIN PGP PUBLIC KEY BLOCK")) {
    showStatus("Public key must be ASCII-armored PGP format", true);
    return;
  }

  // Start from the existing settings so we don't clobber the other backend's
  // stored material when switching back and forth.
  const next = {
    ...currentSettings,
    serviceUrl,
    publicKeyArmored,
    autoSign,
    signerBackend: backend,
  };

  // -- Backend-specific handling --------------------------------------------
  if (backend === BACKENDS.PLAINTEXT) {
    const fingerprint = $("fingerprint").value.trim().toUpperCase();
    const privateKeyArmored = $("private-key").value.trim();
    if (!validateFingerprint(fingerprint)) return;
    if (privateKeyArmored && !privateKeyArmored.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
      showStatus("Private key must be ASCII-armored PGP format", true);
      return;
    }
    next.fingerprint = fingerprint;
    next.privateKeyArmored = privateKeyArmored;
  } else if (backend === BACKENDS.ENCRYPTED) {
    const fingerprint = $("fingerprint").value.trim().toUpperCase();
    if (!validateFingerprint(fingerprint)) return;
    next.fingerprint = fingerprint;

    const pasted = $("private-key-enc").value.trim();
    const pass = $("enc-passphrase").value;
    const confirm = $("enc-passphrase-confirm").value;

    if (pasted) {
      // Encrypt a freshly-pasted key.
      if (!pasted.includes("BEGIN PGP PRIVATE KEY BLOCK")) {
        showStatus("Private key must be ASCII-armored PGP format", true);
        return;
      }
      if (!pass) {
        showStatus("Set an encryption passphrase", true);
        return;
      }
      if (pass !== confirm) {
        showStatus("Passphrases do not match", true);
        return;
      }
      try {
        next.encryptedKey = await encryptPrivateKey(pasted, pass);
      } catch (err) {
        showStatus(`Encryption failed: ${err.message}`, true);
        return;
      }
      // Never keep a plaintext copy once encrypted.
      next.privateKeyArmored = "";
      // Wipe the textarea + passphrases from the DOM.
      $("private-key-enc").value = "";
      $("enc-passphrase").value = "";
      $("enc-passphrase-confirm").value = "";
    } else if (!isEncryptedEnvelope(next.encryptedKey)) {
      showStatus("Paste a private key to encrypt, or use the migrate button", true);
      return;
    }
  } else if (backend === BACKENDS.NATIVE) {
    const fingerprint = $("native-fingerprint").value.trim().toUpperCase();
    if (!validateFingerprint(fingerprint)) return;
    next.fingerprint = fingerprint;
    // Native backend keeps no key material in the browser.
  } else if (backend === BACKENDS.REMOTE) {
    const fingerprint = $("remote-fingerprint").value.trim().toUpperCase();
    if (!validateFingerprint(fingerprint)) return;
    next.fingerprint = fingerprint;
    next.bunkerBaseUrl = $("bunker-base-url").value.trim();
    // Remote backend keeps NO key material in the browser — only pairing state.
  }

  currentSettings = next;
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  showStatus("Settings saved");
  syncBackendPanels();
}

/** Migrate a legacy plaintext key into the encrypted envelope. */
async function migrateToEncrypted() {
  const legacy = currentSettings.privateKeyArmored;
  if (!legacy) {
    showStatus("No legacy plaintext key to migrate", true);
    return;
  }
  const pass = $("enc-passphrase").value;
  const confirm = $("enc-passphrase-confirm").value;
  if (!pass) {
    showStatus("Set an encryption passphrase first", true);
    return;
  }
  if (pass !== confirm) {
    showStatus("Passphrases do not match", true);
    return;
  }
  try {
    const envelope = await encryptPrivateKey(legacy, pass);
    currentSettings = {
      ...currentSettings,
      encryptedKey: envelope,
      privateKeyArmored: "", // remove the plaintext copy
      signerBackend: BACKENDS.ENCRYPTED,
    };
    await chrome.storage.local.set({ [SETTINGS_KEY]: currentSettings });
    $("enc-passphrase").value = "";
    $("enc-passphrase-confirm").value = "";
    $("private-key").value = "";
    showStatus("Legacy key encrypted; plaintext copy removed");
    syncBackendPanels();
  } catch (err) {
    showStatus(`Migration failed: ${err.message}`, true);
  }
}

/** Probe the native-messaging host and update the status badge. */
async function checkNativeHost() {
  const el = $("native-status");
  el.className = "native-status";
  el.textContent = "Checking…";
  try {
    const res = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action: "NATIVE_HOST_PING", payload: {} }, (response) => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(response);
      });
    });
    if (res && res.detected) {
      el.className = "native-status detected";
      el.textContent = res.fingerprint
        ? `Native host detected. gpg key: ${res.fingerprint}`
        : "Native host detected.";
      if (res.fingerprint && !$("native-fingerprint").value) {
        $("native-fingerprint").value = res.fingerprint;
      }
    } else {
      el.className = "native-status missing";
      el.textContent = `Native host not detected. ${(res && res.error) || ""}`.trim();
    }
  } catch (err) {
    el.className = "native-status missing";
    el.textContent = `Native host not detected. ${err.message}`;
  }
}

async function clearAllData() {
  if (!confirm("This will clear your PGP key, fingerprint, and all cached tokens. Continue?")) {
    return;
  }
  await chrome.storage.local.remove(SETTINGS_KEY);

  const all = await chrome.storage.local.get(null);
  const tokenKeys = Object.keys(all).filter((k) => k.startsWith(TOKEN_STORAGE_PREFIX));
  if (tokenKeys.length > 0) await chrome.storage.local.remove(tokenKeys);

  currentSettings = { ...DEFAULTS };
  $("fingerprint").value = "";
  $("service-url").value = "";
  $("private-key").value = "";
  $("private-key-enc").value = "";
  $("enc-passphrase").value = "";
  $("enc-passphrase-confirm").value = "";
  $("native-fingerprint").value = "";
  $("public-key").value = "";
  $("auto-sign").checked = false;
  setBackendRadio(BACKENDS.PLAINTEXT);
  syncBackendPanels();
  showStatus("All data cleared");
}

/**
 * Create a CapAuth Bunker pairing session and render the QR.
 *
 * Calls POST {base}/bunker/session on the configured CapAuth service, stores the
 * returned session id + pairing secret + relay URL in settings (so the `remote`
 * backend can connect), and shows the QR for the phone to scan.
 */
async function pairBunker() {
  const base = $("bunker-base-url").value.trim().replace(/\/+$/, "");
  if (!base) {
    showStatus("Set the CapAuth service base URL first", true);
    return;
  }
  $("bunker-status").textContent = "Creating pairing session…";
  try {
    const resp = await fetch(base + "/bunker/session", { method: "POST" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();

    // Persist pairing state into settings so the remote backend can use it.
    currentSettings = {
      ...currentSettings,
      bunkerBaseUrl: base,
      signerBackend: BACKENDS.REMOTE,
      bunkerPairing: {
        sessionId: data.session_id,
        pairingSecret: data.pairing_secret,
        relayWsUrl: data.relay_ws_url,
      },
    };
    await chrome.storage.local.set({ [SETTINGS_KEY]: currentSettings });

    if (data.qr_data_url) {
      $("bunker-qr-img").src = data.qr_data_url;
      $("bunker-qr").style.display = "block";
    }
    $("bunker-uri").textContent = data.pairing_uri;
    $("bunker-status").textContent =
      "Scan this on your phone. Session expires in " + (data.expires_in || 300) + "s.";
  } catch (err) {
    $("bunker-status").textContent = "Pairing failed: " + err.message;
  }
}

function showStatus(message, isError = false) {
  const status = $("save-status");
  status.textContent = message;
  status.style.display = "block";
  status.style.color = isError ? "#ef4444" : "#10b981";
  setTimeout(() => {
    status.style.display = "none";
  }, 3000);
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();

  document.querySelectorAll('input[name="signer-backend"]').forEach((r) => {
    r.addEventListener("change", syncBackendPanels);
  });

  $("btn-save").addEventListener("click", saveSettings);
  $("btn-clear").addEventListener("click", clearAllData);
  $("btn-migrate").addEventListener("click", migrateToEncrypted);
  $("btn-native-check").addEventListener("click", checkNativeHost);
  $("btn-bunker-pair").addEventListener("click", pairBunker);
});
