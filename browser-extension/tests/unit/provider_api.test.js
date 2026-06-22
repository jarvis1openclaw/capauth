/**
 * Tests for the page-facing `window.capauth` provider (content_scripts/provider.js).
 *
 * We load the provider into a happy-dom window and simulate the isolated-world
 * bridge by intercepting window.postMessage. These assert the public API
 * contract:
 *   - window.capauth is injected, frozen, and feature-detectable.
 *   - signChallenge forwards ONLY server fields (it strips any page-supplied
 *     `origin` so the page can never influence Tier B binding).
 *   - getFingerprint resolves to the bridge-provided fingerprint.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { webcrypto } from "crypto";

const here = dirname(fileURLToPath(import.meta.url));
const providerSrc = readFileSync(
  join(here, "..", "..", "content_scripts", "provider.js"),
  "utf-8"
);

/**
 * Minimal window stub with the surface provider.js needs: addEventListener /
 * postMessage (loopback via a microtask), location.origin, CustomEvent,
 * dispatchEvent, crypto.randomUUID, defineProperty. A FRESH one per test means
 * the provider's non-configurable `window.capauth` never collides across tests.
 */
function makeWindow() {
  const listeners = { message: [] };
  const win = {
    location: { origin: "https://page.example" },
    crypto: webcrypto,
    addEventListener(type, cb) {
      (listeners[type] = listeners[type] || []).push(cb);
    },
    removeEventListener(type, cb) {
      listeners[type] = (listeners[type] || []).filter((l) => l !== cb);
    },
    dispatchEvent() {
      return true;
    },
    postMessage(data) {
      // Loopback: deliver asynchronously to all message listeners, source=win.
      queueMicrotask(() => {
        for (const cb of listeners.message || []) {
          cb({ source: win, origin: win.location.origin, data });
        }
      });
    },
    CustomEvent: class {
      constructor(type, init) {
        this.type = type;
        this.detail = (init && init.detail) || null;
      }
    },
  };
  return win;
}

/**
 * Install a fake bridge: capture page->ext messages, auto-reply ext->page.
 * `onRequest(method, params)` returns the `result` for that request.
 */
function installFakeBridge(win, onRequest) {
  const requests = [];
  win.addEventListener("message", (event) => {
    const data = event.data;
    if (!data || data.__capauth !== true || data.direction !== "page->ext") return;
    requests.push(data);
    Promise.resolve(onRequest(data.method, data.params)).then((result) => {
      win.postMessage(
        { __capauth: true, direction: "ext->page", requestId: data.requestId, ok: true, result },
        "*"
      );
    });
  });
  return requests;
}

function loadProvider(win) {
  // Evaluate provider.js with `window`/`crypto` bound to our stub window.
  const fn = new Function("window", "crypto", providerSrc);
  fn(win, win.crypto);
}

describe("window.capauth provider API", () => {
  let win;

  beforeEach(() => {
    win = makeWindow();
  });

  it("injects a frozen, feature-detectable window.capauth", () => {
    loadProvider(win);
    expect(win.capauth).toBeTruthy();
    expect(win.capauth.isCapAuth).toBe(true);
    expect(typeof win.capauth.getFingerprint).toBe("function");
    expect(typeof win.capauth.signChallenge).toBe("function");
    expect(Object.isFrozen(win.capauth)).toBe(true);
  });

  it("getFingerprint resolves the bridge-provided fingerprint", async () => {
    installFakeBridge(win, (method) => {
      if (method === "getFingerprint") return { fingerprint: "ABC123" };
      return {};
    });
    loadProvider(win);
    const fp = await win.capauth.getFingerprint();
    expect(fp).toBe("ABC123");
  });

  it("signChallenge forwards ONLY server fields (strips page-supplied origin)", async () => {
    let seenParams = null;
    installFakeBridge(win, (method, params) => {
      if (method === "signChallenge") {
        seenParams = params;
        return { signature: "SIG", fingerprint: "FP", origin: "https://real.example" };
      }
      return {};
    });
    loadProvider(win);

    const res = await win.capauth.signChallenge({
      nonce: "n-1",
      client_nonce_echo: "cn",
      timestamp: "t",
      service: "svc",
      expires: "e",
      origin: "https://evil.example", // page tries to inject — must be dropped
    });

    expect(res.signature).toBe("SIG");
    // The provider must NOT forward the page's origin to the bridge.
    expect(seenParams).toBeTruthy();
    expect("origin" in seenParams).toBe(false);
    expect(seenParams.nonce).toBe("n-1");
    expect(seenParams.client_nonce_echo).toBe("cn");
  });

  it("signChallenge rejects when no nonce is provided", async () => {
    installFakeBridge(win, () => ({}));
    loadProvider(win);
    await expect(win.capauth.signChallenge({})).rejects.toThrow(/nonce/);
  });
});
