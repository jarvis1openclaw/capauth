/**
 * CapAuth browser extension — background service worker.
 *
 * Handles the full CapAuth passwordless PGP authentication flow:
 *   1. Fetch challenge nonce from a CapAuth-enabled service
 *   2. Sign the canonical nonce payload with the user's PGP key
 *   3. Optionally sign profile claims
 *   4. POST signed response and receive an OIDC-compatible JWT
 *   5. Cache tokens with TTL management
 *
 * All communication with the popup and content scripts uses
 * chrome.runtime.sendMessage with { action, payload } shape,
 * following the pattern established by Consciousness Swipe.
 *
 * @module background
 */

import {
  generateNonce,
  buildCanonicalNoncePayload,
  buildCanonicalClaimsPayload,
  signMessage,
  verifySignature,
} from "./lib/openpgp-bundle.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CAPAUTH_VERSION = "1.0";
const NONCE_TTL_MS = 60_000; // 60 seconds — nonce expiry window
const TOKEN_STORAGE_PREFIX = "capauth_token_";
const SETTINGS_KEY = "capauth_settings";

// ---------------------------------------------------------------------------
// In-memory key unlock session
// ---------------------------------------------------------------------------
//
// The unlocked passphrase is held in service-worker memory ONLY (never written
// to storage) so `window.capauth.signChallenge()` can sign without re-prompting
// on every call. It is cleared when the session expires or the worker restarts.
//
// STUB (follow-up): at-rest encryption of the stored private key. Today the
// armored private key lives in chrome.storage.local (see options.js). The
// intended hardening is to store it encrypted (passphrase-derived key via
// WebCrypto PBKDF2/AES-GCM) and decrypt into memory on unlock. The unlock
// plumbing below is structured for that; the encryption itself is not yet
// implemented — documented in browser-extension/README.md.
const UNLOCK_TTL_MS = 15 * 60_000; // 15 min unlock window
let unlockSession = null; // { passphrase, unlockedAt, expiresAt }

function isUnlocked() {
  return !!(unlockSession && Date.now() < unlockSession.expiresAt);
}

function setUnlock(passphrase) {
  unlockSession = {
    passphrase: passphrase || "",
    unlockedAt: Date.now(),
    expiresAt: Date.now() + UNLOCK_TTL_MS,
  };
}

function clearUnlock() {
  unlockSession = null;
}

/**
 * Resolve the passphrase to use for signing.
 *
 * Precedence: an explicit per-call passphrase > the active unlock session > "".
 * An empty string is valid for unprotected keys.
 */
function resolvePassphrase(explicit) {
  if (explicit) return explicit;
  if (isUnlocked()) return unlockSession.passphrase;
  return "";
}

// ---------------------------------------------------------------------------
// Origin-consent prompts (anti-phishing)
// ---------------------------------------------------------------------------
//
// pendingConsent: requestId -> { resolve, origin, fingerprint, createdAt }
// The popup renders these and calls back with PROVIDER_CONSENT_RESOLVE.
const pendingConsent = new Map();

function makeConsentId() {
  return (crypto.randomUUID && crypto.randomUUID()) || `c-${Date.now()}-${Math.random()}`;
}

/**
 * Ask the user to approve signing for a specific origin.
 *
 * Opens the extension popup (which lists pending consents and shows the REAL
 * requesting origin so a phished user sees `https://evil.example`). Resolves
 * with true (allow) / false (deny). Auto-denies after 60s.
 *
 * @param {string} origin - The browser-attested origin requesting a signature.
 * @param {string} fingerprint - Fingerprint that would sign.
 * @returns {Promise<boolean>}
 */
function requestOriginConsent(origin, fingerprint) {
  return new Promise((resolve) => {
    const id = makeConsentId();
    const timer = setTimeout(() => {
      if (pendingConsent.has(id)) {
        pendingConsent.delete(id);
        resolve(false);
      }
    }, 60_000);

    pendingConsent.set(id, {
      resolve: (allow) => {
        clearTimeout(timer);
        resolve(allow);
      },
      origin,
      fingerprint,
      createdAt: Date.now(),
    });

    // Surface a badge + try to open the popup so the user sees the prompt.
    try {
      chrome.action.setBadgeText({ text: String(pendingConsent.size) });
      chrome.action.setBadgeBackgroundColor({ color: "#7C3AED" });
    } catch {
      /* setBadge unavailable in some contexts */
    }
    if (chrome.action.openPopup) {
      chrome.action.openPopup().catch(() => {});
    }
  });
}

// ---------------------------------------------------------------------------
// CapAuth Client
// ---------------------------------------------------------------------------

/**
 * CapAuth authentication client.
 *
 * Encapsulates the challenge-response flow against a CapAuth verification
 * service. Designed for use inside a Chrome MV3 service worker.
 */
class CapAuthClient {
  /**
   * Fetch a challenge nonce from the CapAuth service.
   *
   * Sends the client's fingerprint and a random client nonce to the
   * server's /capauth/v1/challenge endpoint. The server responds with
   * its own nonce, echoes our client nonce, and provides a timestamp
   * and expiry window.
   *
   * @param {string} serviceUrl - Base URL of the service (e.g. "https://nextcloud.skworld.io").
   * @param {string} fingerprint - Client's 40-character PGP fingerprint.
   * @param {string} clientNonce - Base64-encoded random client nonce.
   * @returns {Promise<Object>} Challenge response from the server.
   * @throws {Error} On network failure or invalid server response.
   */
  async fetchChallenge(serviceUrl, fingerprint, clientNonce) {
    const challengeUrl = `${serviceUrl.replace(/\/$/, "")}/capauth/v1/challenge`;

    const body = {
      capauth_version: CAPAUTH_VERSION,
      fingerprint,
      client_nonce: clientNonce,
      requested_service: new URL(serviceUrl).hostname,
    };

    const response = await fetch(challengeUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const detail = errorData.error_description || errorData.error || response.statusText;
      throw new Error(`Challenge request failed (${response.status}): ${detail}`);
    }

    const data = await response.json();

    // Validate required fields
    const required = ["nonce", "client_nonce_echo", "timestamp", "service", "expires"];
    for (const field of required) {
      if (!data[field]) {
        throw new Error(`Challenge response missing required field: ${field}`);
      }
    }

    // Verify the server echoed our client nonce correctly (prevents precomputed challenges)
    if (data.client_nonce_echo !== clientNonce) {
      throw new Error("Server did not echo our client nonce correctly. Possible MITM attack.");
    }

    return data;
  }

  /**
   * Sign the canonical nonce payload with the client's private key.
   *
   * Builds the same canonical string that the server will verify,
   * matching the Python canonical_nonce_payload() format exactly.
   *
   * @param {Object} challenge - Challenge response from fetchChallenge().
   * @param {string} privateKeyArmored - ASCII-armored PGP private key.
   * @param {string} [passphrase=''] - Passphrase to unlock the private key.
   * @returns {Promise<string>} ASCII-armored PGP detached signature.
   */
  async signNonce(challenge, privateKeyArmored, passphrase = "") {
    // Origin-binding (Tier A): if the server asserted an `origin` in the
    // challenge, sign the V2 origin-bound payload; otherwise sign legacy V1
    // (dual-accept migration). TIER B (the real phishing fix, out of scope
    // here): override with `window.location.origin` of the page actually being
    // authenticated so the server rejects a relayed/proxied origin.
    const canonicalPayload = buildCanonicalNoncePayload({
      nonce: challenge.nonce,
      clientNonce: challenge.client_nonce_echo,
      origin: challenge.origin,
      timestamp: challenge.timestamp,
      service: challenge.service,
      expires: challenge.expires,
    });

    return await signMessage(canonicalPayload, privateKeyArmored, passphrase);
  }

  /**
   * Sign profile claims bound to the nonce.
   *
   * @param {string} fingerprint - Client's PGP fingerprint.
   * @param {string} nonce - The challenge nonce UUID.
   * @param {Object} claims - Profile claims to assert.
   * @param {string} privateKeyArmored - ASCII-armored PGP private key.
   * @param {string} [passphrase=''] - Passphrase to unlock the private key.
   * @returns {Promise<string>} ASCII-armored PGP detached signature over claims.
   */
  async signClaims(fingerprint, nonce, claims, privateKeyArmored, passphrase = "") {
    const canonicalPayload = buildCanonicalClaimsPayload({
      fingerprint,
      nonce,
      claims,
    });

    return await signMessage(canonicalPayload, privateKeyArmored, passphrase);
  }

  /**
   * POST the signed authentication response to the CapAuth verify endpoint.
   *
   * On success, the server returns OIDC-compatible claims and a JWT access token.
   *
   * @param {string} serviceUrl - Base URL of the service.
   * @param {Object} params
   * @param {string} params.fingerprint - Client's PGP fingerprint.
   * @param {string} params.nonce - Challenge nonce UUID.
   * @param {string} params.nonceSignature - ASCII-armored PGP signature over canonical nonce.
   * @param {Object} [params.claims={}] - Profile claims.
   * @param {string} [params.claimsSignature=''] - PGP signature over canonical claims.
   * @param {string} [params.publicKey=''] - ASCII-armored public key (for enrollment).
   * @returns {Promise<Object>} Verify response with access_token, oidc_claims, etc.
   * @throws {Error} On network failure, rejected signature, or enrollment issue.
   */
  async verifyResponse(serviceUrl, {
    fingerprint,
    nonce,
    nonceSignature,
    claims = {},
    claimsSignature = "",
    publicKey = "",
  }) {
    const verifyUrl = `${serviceUrl.replace(/\/$/, "")}/capauth/v1/verify`;

    const body = {
      capauth_version: CAPAUTH_VERSION,
      fingerprint,
      nonce,
      nonce_signature: nonceSignature,
      claims,
      claims_signature: claimsSignature,
      public_key: publicKey,
    };

    const response = await fetch(verifyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (response.status === 401) {
      const data = await response.json().catch(() => ({}));
      throw new Error(
        `Authentication rejected: ${data.error || "signature_verification_failed"}`
      );
    }

    if (response.status === 403) {
      const data = await response.json().catch(() => ({}));
      if (data.status === "enrollment_pending") {
        throw new Error("Your key requires administrator approval before first login.");
      }
      throw new Error("Access forbidden. Your key may not be enrolled on this service.");
    }

    if (!response.ok) {
      throw new Error(`Verify request failed (${response.status}): ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Cache an access token for a service in chrome.storage.local.
   *
   * Stores the token with a timestamp so we can check expiry later.
   *
   * @param {string} serviceUrl - Service base URL (used as storage key).
   * @param {Object} tokenResponse - Full verify response containing access_token.
   */
  async cacheToken(serviceUrl, tokenResponse) {
    const hostname = new URL(serviceUrl).hostname;
    const key = `${TOKEN_STORAGE_PREFIX}${hostname}`;

    await chrome.storage.local.set({
      [key]: {
        ...tokenResponse,
        cached_at: new Date().toISOString(),
        service_url: serviceUrl,
      },
    });
  }

  /**
   * Retrieve a cached token for a service, if it exists and has not expired.
   *
   * @param {string} serviceUrl - Service base URL.
   * @returns {Promise<Object|null>} Cached token response, or null if expired/missing.
   */
  async getCachedToken(serviceUrl) {
    const hostname = new URL(serviceUrl).hostname;
    const key = `${TOKEN_STORAGE_PREFIX}${hostname}`;

    const result = await chrome.storage.local.get(key);
    const cached = result[key];

    if (!cached) return null;

    // Check expiry
    const cachedAt = new Date(cached.cached_at).getTime();
    const expiresIn = (cached.expires_in || 3600) * 1000;
    if (Date.now() > cachedAt + expiresIn) {
      // Token expired — clean up
      await chrome.storage.local.remove(key);
      return null;
    }

    return cached;
  }
}

const client = new CapAuthClient();

// ---------------------------------------------------------------------------
// Nonce lifecycle management
// ---------------------------------------------------------------------------

/**
 * Active nonces awaiting signature. Keyed by nonce UUID.
 * Each entry has a timeout that clears it after NONCE_TTL_MS.
 */
const pendingNonces = new Map();

/**
 * Track a nonce and auto-expire it after the TTL window.
 *
 * @param {string} nonceId - The nonce UUID from the challenge.
 * @param {Object} challengeData - Full challenge response to store.
 */
function trackNonce(nonceId, challengeData) {
  // Clear any existing timeout for this nonce
  if (pendingNonces.has(nonceId)) {
    clearTimeout(pendingNonces.get(nonceId).timeoutId);
  }

  const timeoutId = setTimeout(() => {
    pendingNonces.delete(nonceId);
  }, NONCE_TTL_MS);

  pendingNonces.set(nonceId, {
    challenge: challengeData,
    created: Date.now(),
    timeoutId,
  });
}

/**
 * Consume a pending nonce (removes it from tracking).
 *
 * @param {string} nonceId - The nonce UUID.
 * @returns {Object|null} The challenge data, or null if expired/missing.
 */
function consumeNonce(nonceId) {
  const entry = pendingNonces.get(nonceId);
  if (!entry) return null;

  clearTimeout(entry.timeoutId);
  pendingNonces.delete(nonceId);
  return entry.challenge;
}

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

/**
 * Load extension settings from chrome.storage.local.
 *
 * @returns {Promise<Object>} Settings object with fingerprint, serviceUrl, etc.
 */
async function loadSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  return result[SETTINGS_KEY] || {};
}

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------

/**
 * Central message dispatcher.
 *
 * All messages follow the { action, payload } shape established by
 * Consciousness Swipe. Actions:
 *
 *   INITIATE_AUTH    — Start the full auth flow for a service
 *   CHECK_STATUS     — Check connection status and stored fingerprint
 *   SIGN_CHALLENGE   — Sign a specific challenge nonce (for manual flow)
 *   GET_FINGERPRINT  — Return the stored fingerprint
 *   GET_CACHED_TOKEN — Check for a cached token for a service
 *   CLEAR_TOKENS     — Clear all cached tokens
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const { action, payload } = message;

  switch (action) {
    case "INITIATE_AUTH":
      handleInitiateAuth(payload).then(sendResponse);
      break;

    case "CHECK_STATUS":
      handleCheckStatus().then(sendResponse);
      break;

    case "SIGN_CHALLENGE":
      handleSignChallenge(payload).then(sendResponse);
      break;

    case "GET_FINGERPRINT":
      handleGetFingerprint().then(sendResponse);
      break;

    case "GET_CACHED_TOKEN":
      handleGetCachedToken(payload).then(sendResponse);
      break;

    case "CLEAR_TOKENS":
      handleClearTokens().then(sendResponse);
      break;

    case "QR_LOGIN":
      handleQRLogin(payload).then(sendResponse);
      break;

    // --- window.capauth provider (NIP-07 analog) ---
    case "PROVIDER_GET_FINGERPRINT":
      handleProviderGetFingerprint(payload).then(sendResponse);
      break;

    case "PROVIDER_SIGN_CHALLENGE":
      handleProviderSignChallenge(payload).then(sendResponse);
      break;

    // --- key unlock session ---
    case "UNLOCK_KEY":
      handleUnlockKey(payload).then(sendResponse);
      break;

    case "LOCK_KEY":
      clearUnlock();
      sendResponse({ success: true, unlocked: false });
      break;

    case "UNLOCK_STATUS":
      sendResponse({ success: true, unlocked: isUnlocked() });
      break;

    // --- origin-consent (popup callbacks) ---
    case "PROVIDER_LIST_CONSENTS":
      sendResponse({ success: true, consents: listPendingConsents() });
      break;

    case "PROVIDER_CONSENT_RESOLVE":
      sendResponse(resolveConsent(payload));
      break;

    default:
      sendResponse({ error: `Unknown action: ${action}` });
  }

  // Return true to keep the message channel open for async responses
  return true;
});

// ---------------------------------------------------------------------------
// Action handlers
// ---------------------------------------------------------------------------

/**
 * Initiate the full CapAuth authentication flow.
 *
 * Flow:
 *   1. Generate client nonce
 *   2. Fetch challenge from service
 *   3. Sign the canonical nonce payload
 *   4. Optionally sign profile claims
 *   5. POST to /capauth/v1/verify
 *   6. Cache the returned JWT
 *
 * @param {Object} payload
 * @param {string} payload.serviceUrl - Service to authenticate with.
 * @param {string} [payload.fingerprint] - Override fingerprint (defaults to stored).
 * @param {string} [payload.privateKeyArmored] - PGP private key for signing.
 * @param {string} [payload.passphrase] - Key passphrase.
 * @param {Object} [payload.claims] - Profile claims to assert.
 * @param {string} [payload.publicKey] - Public key for enrollment.
 * @returns {Promise<Object>} Result with success, token, and auth details.
 */
async function handleInitiateAuth(payload) {
  const {
    serviceUrl,
    fingerprint: fpOverride,
    privateKeyArmored,
    passphrase = "",
    claims = {},
    publicKey = "",
  } = payload || {};

  if (!serviceUrl) {
    return { success: false, error: "serviceUrl is required" };
  }

  try {
    // Resolve fingerprint
    const settings = await loadSettings();
    const fingerprint = fpOverride || settings.fingerprint;
    if (!fingerprint) {
      return {
        success: false,
        error: "No PGP fingerprint configured. Open extension settings to set up your identity.",
      };
    }

    // Resolve private key
    const keyArmored = privateKeyArmored || settings.privateKeyArmored;
    if (!keyArmored) {
      return {
        success: false,
        error: "No private key available. Import your PGP private key in extension settings.",
      };
    }

    // Check for cached token first
    const cached = await client.getCachedToken(serviceUrl);
    if (cached) {
      return {
        success: true,
        source: "cache",
        fingerprint,
        access_token: cached.access_token,
        oidc_claims: cached.oidc_claims || {},
        expires_in: cached.expires_in,
      };
    }

    // Step 1: Generate client nonce
    const clientNonce = generateNonce();

    // Step 2: Fetch challenge
    const challenge = await client.fetchChallenge(serviceUrl, fingerprint, clientNonce);

    // Track the nonce for TTL management
    trackNonce(challenge.nonce, challenge);

    // Step 3: Sign the nonce
    const nonceSignature = await client.signNonce(challenge, keyArmored, passphrase);

    // Step 4: Optionally sign claims
    let claimsSignature = "";
    if (Object.keys(claims).length > 0) {
      claimsSignature = await client.signClaims(
        fingerprint,
        challenge.nonce,
        claims,
        keyArmored,
        passphrase
      );
    }

    // Step 5: POST verify
    const verifyResult = await client.verifyResponse(serviceUrl, {
      fingerprint,
      nonce: challenge.nonce,
      nonceSignature,
      claims,
      claimsSignature,
      publicKey: publicKey || settings.publicKeyArmored || "",
    });

    // Consume the nonce (it has been used)
    consumeNonce(challenge.nonce);

    // Step 6: Cache the token
    await client.cacheToken(serviceUrl, verifyResult);

    return {
      success: true,
      source: "fresh",
      fingerprint,
      access_token: verifyResult.access_token,
      oidc_claims: verifyResult.oidc_claims || {},
      expires_in: verifyResult.expires_in,
      is_new_enrollment: verifyResult.is_new_enrollment || false,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Check status: is a fingerprint configured, and is it valid?
 *
 * @returns {Promise<Object>} Status with configured fingerprint and connection info.
 */
async function handleCheckStatus() {
  try {
    const settings = await loadSettings();
    const fingerprint = settings.fingerprint || "";
    const hasPrivateKey = !!settings.privateKeyArmored;
    const serviceUrl = settings.serviceUrl || "";

    let serviceReachable = false;
    if (serviceUrl) {
      try {
        const statusUrl = `${serviceUrl.replace(/\/$/, "")}/capauth/v1/status`;
        const resp = await fetch(statusUrl, { method: "GET" });
        serviceReachable = resp.ok;
      } catch {
        // Service unreachable
      }
    }

    return {
      configured: !!fingerprint,
      fingerprint,
      hasPrivateKey,
      serviceUrl,
      serviceReachable,
    };
  } catch (err) {
    return { configured: false, error: err.message };
  }
}

/**
 * Sign a specific challenge nonce (manual/advanced flow).
 *
 * Used when the content script detects a CapAuth login page and the
 * user clicks "Sign in with CapAuth" — the challenge may have been
 * fetched by the page itself.
 *
 * @param {Object} payload
 * @param {Object} payload.challenge - Challenge response object.
 * @param {string} [payload.privateKeyArmored] - PGP private key override.
 * @param {string} [payload.passphrase] - Key passphrase.
 * @returns {Promise<Object>} Signed nonce result.
 */
async function handleSignChallenge(payload) {
  const { challenge, privateKeyArmored, passphrase = "" } = payload || {};

  if (!challenge || !challenge.nonce) {
    return { success: false, error: "Challenge object with nonce is required" };
  }

  try {
    const settings = await loadSettings();
    const keyArmored = privateKeyArmored || settings.privateKeyArmored;
    if (!keyArmored) {
      return { success: false, error: "No private key available." };
    }

    const signature = await client.signNonce(challenge, keyArmored, passphrase);
    return { success: true, signature };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Return the stored PGP fingerprint.
 *
 * @returns {Promise<Object>} Object with fingerprint string.
 */
async function handleGetFingerprint() {
  try {
    const settings = await loadSettings();
    return {
      success: true,
      fingerprint: settings.fingerprint || "",
      configured: !!settings.fingerprint,
    };
  } catch (err) {
    return { success: false, error: err.message, fingerprint: "" };
  }
}

/**
 * Check for a cached token for a specific service.
 *
 * @param {Object} payload
 * @param {string} payload.serviceUrl - Service URL to check.
 * @returns {Promise<Object>} Cached token or null.
 */
async function handleGetCachedToken(payload) {
  const { serviceUrl } = payload || {};
  if (!serviceUrl) {
    return { success: false, error: "serviceUrl is required" };
  }

  try {
    const cached = await client.getCachedToken(serviceUrl);
    return {
      success: true,
      hasToken: !!cached,
      token: cached,
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Clear all cached tokens from storage.
 *
 * @returns {Promise<Object>} Result of the clear operation.
 */
async function handleClearTokens() {
  try {
    const all = await chrome.storage.local.get(null);
    const tokenKeys = Object.keys(all).filter((k) => k.startsWith(TOKEN_STORAGE_PREFIX));
    if (tokenKeys.length > 0) {
      await chrome.storage.local.remove(tokenKeys);
    }
    return { success: true, cleared: tokenKeys.length };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Open the QR login page for mobile-to-desktop authentication.
 *
 * Opens the CapAuth service's QR login page in a new tab. The page
 * generates a QR code for the mobile device to scan and polls for
 * completion.
 *
 * @param {Object} payload
 * @param {string} [payload.redirect] - URL to redirect after authentication.
 * @returns {Promise<Object>} Result with the QR login page URL.
 */
async function handleQRLogin(payload) {
  const { redirect = "" } = payload || {};

  try {
    const settings = await loadSettings();
    const serviceUrl = settings.serviceUrl;
    if (!serviceUrl) {
      return {
        success: false,
        error: "No service URL configured. Open extension settings.",
      };
    }

    const qrUrl = new URL("/capauth/v1/qr-login", serviceUrl);
    if (redirect) {
      qrUrl.searchParams.set("redirect", redirect);
    }

    // Open the QR login page in a new tab
    await chrome.tabs.create({ url: qrUrl.toString() });

    return { success: true, url: qrUrl.toString() };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// window.capauth provider handlers (NIP-07 analog)
// ---------------------------------------------------------------------------

/**
 * Provider: return the configured fingerprint to the page (no key material).
 *
 * @param {Object} payload
 * @param {string} payload.origin - Browser-attested requesting origin (logged).
 * @returns {Promise<Object>} { success, fingerprint }
 */
async function handleProviderGetFingerprint(payload) {
  try {
    const settings = await loadSettings();
    const fingerprint = settings.fingerprint || "";
    if (!fingerprint) {
      return { success: false, error: "No PGP identity configured in CapAuth." };
    }
    return { success: true, fingerprint };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Provider: sign a challenge for `window.capauth.signChallenge()`.
 *
 * TIER B ORIGIN-BINDING — the load-bearing handler:
 *   - `payload.challenge.origin` and `payload.origin` are set by the ISOLATED-
 *     world bridge from the real `window.location.origin`; the page cannot
 *     forge them.
 *   - We ALWAYS build the V2 canonical payload with that origin (never V1, and
 *     never an origin supplied by the page itself).
 *   - The user must approve the specific origin (phishing-resistant consent —
 *     the popup shows the real origin, so a relayed login on evil.example
 *     surfaces evil.example).
 *
 * The private key never leaves the service worker. Signing uses the unlocked
 * session passphrase (or an unprotected key).
 *
 * @param {Object} payload
 * @param {Object} payload.challenge - Challenge incl. browser-attested origin.
 * @param {string} payload.origin - The browser-attested origin (duplicate).
 * @returns {Promise<Object>} { success, signature, fingerprint, origin, canonical }
 */
async function handleProviderSignChallenge(payload) {
  const { challenge, origin } = payload || {};

  if (!challenge || !challenge.nonce) {
    return { success: false, error: "Challenge with a nonce is required." };
  }
  if (!origin || !challenge.origin || origin !== challenge.origin) {
    // Defensive: the bridge sets both from the same source; a mismatch means
    // tampering. Refuse rather than sign an ambiguous origin.
    return { success: false, error: "Origin attestation missing or inconsistent." };
  }

  try {
    const settings = await loadSettings();
    const fingerprint = settings.fingerprint || "";
    const keyArmored = settings.privateKeyArmored || "";
    if (!fingerprint || !keyArmored) {
      return { success: false, error: "No PGP key configured. Import your key in CapAuth settings." };
    }

    // Phishing-resistant consent: the user must approve THIS origin.
    const allowed = await requestOriginConsent(origin, fingerprint);
    if (!allowed) {
      return { success: false, error: `Signing denied for origin ${origin}.` };
    }

    // Build the EXACT CAPAUTH_NONCE_V2 bytes (origin = the real page origin).
    const canonical = buildCanonicalNoncePayload({
      nonce: challenge.nonce,
      clientNonce: challenge.client_nonce_echo,
      origin, // Tier B: browser-attested, never page-supplied
      timestamp: challenge.timestamp,
      service: challenge.service,
      expires: challenge.expires,
    });

    const passphrase = resolvePassphrase(challenge.passphrase);
    const signature = await signMessage(canonical, keyArmored, passphrase);

    return { success: true, signature, fingerprint, origin, canonical };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Unlock the signing key for the current service-worker session.
 *
 * Verifies the passphrase actually decrypts the stored key, then caches it in
 * memory (never storage) for UNLOCK_TTL_MS.
 *
 * @param {Object} payload
 * @param {string} payload.passphrase
 * @returns {Promise<Object>} { success, unlocked }
 */
async function handleUnlockKey(payload) {
  const { passphrase = "" } = payload || {};
  try {
    const settings = await loadSettings();
    const keyArmored = settings.privateKeyArmored || "";
    if (!keyArmored) {
      return { success: false, error: "No private key imported." };
    }
    // Prove the passphrase works by performing a throwaway signature.
    await signMessage("capauth-unlock-probe", keyArmored, passphrase);
    setUnlock(passphrase);
    return { success: true, unlocked: true };
  } catch (err) {
    clearUnlock();
    return { success: false, error: "Incorrect passphrase or unreadable key." };
  }
}

// --- origin-consent registry helpers (popup-facing) ---

function listPendingConsents() {
  return Array.from(pendingConsent.entries()).map(([id, c]) => ({
    id,
    origin: c.origin,
    fingerprint: c.fingerprint,
    createdAt: c.createdAt,
  }));
}

function resolveConsent(payload) {
  const { id, allow } = payload || {};
  const entry = pendingConsent.get(id);
  if (!entry) return { success: false, error: "Unknown or expired consent request." };
  pendingConsent.delete(id);
  entry.resolve(!!allow);
  try {
    const remaining = pendingConsent.size;
    chrome.action.setBadgeText({ text: remaining ? String(remaining) : "" });
  } catch {
    /* ignore */
  }
  return { success: true };
}

// ---------------------------------------------------------------------------
// Token expiry cleanup — periodic sweep via chrome.alarms
// ---------------------------------------------------------------------------

chrome.alarms.create("capauth_token_cleanup", { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "capauth_token_cleanup") return;

  try {
    const all = await chrome.storage.local.get(null);
    const expiredKeys = [];

    for (const [key, value] of Object.entries(all)) {
      if (!key.startsWith(TOKEN_STORAGE_PREFIX)) continue;
      if (!value.cached_at) continue;

      const cachedAt = new Date(value.cached_at).getTime();
      const expiresIn = (value.expires_in || 3600) * 1000;
      if (Date.now() > cachedAt + expiresIn) {
        expiredKeys.push(key);
      }
    }

    if (expiredKeys.length > 0) {
      await chrome.storage.local.remove(expiredKeys);
    }
  } catch {
    // Non-fatal — cleanup will retry on next alarm
  }
});
