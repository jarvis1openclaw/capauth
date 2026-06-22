/**
 * CapAuth Bunker — phone-side signer transport + protocol (SPIKE).
 *
 * The phone connects to the broker as `role=signer`, waits for `paired`, then
 * for each `sign_request` raises an approval callback (origin + fingerprint +
 * payload). On approve it signs the EXACT relayed canonical bytes with the
 * phone's OpenPGP key and returns `sign_response`; on reject it returns
 * `reject`. The key never leaves the phone.
 *
 * Bunker protocol (mirror of src/capauth/service/bunker.py):
 *   broker -> signer: {type:"paired"} ...then relayed...
 *   client -> signer: {type:"sign_request", id, payload, origin, fingerprint}
 *   signer -> client: {type:"sign_response", id, signature, fingerprint}
 *                     {type:"reject", id, reason}
 *
 * @module bunker-signer
 */

import { parseCanonical, rebuildCanonicalV2 } from "./canonical.js";
import { E2ESession } from "./bunker-e2e.js";

/**
 * Run the signer loop over a WebSocket relay.
 *
 * @param {Object} opts
 * @param {string} opts.relayWsUrl   - wss://.../bunker/ws
 * @param {string} opts.sessionId    - paired session id (from the QR)
 * @param {string} opts.pairingSecret- pairing secret (from the QR `key`)
 * @param {function(Object): Promise<boolean>} opts.requestApproval - shown the
 *   {payload, origin, fingerprint, fields, version}; resolves true to approve.
 * @param {function(string): Promise<string>} opts.sign - signs the canonical
 *   bytes, returns armored detached signature (key stays in this closure).
 * @param {function(): string} opts.getFingerprint - the phone key's fp.
 * @param {function(string): void} [opts.onStatus] - status callbacks.
 * @param {function(): WebSocket} [opts.makeSocket] - injectable for tests.
 * @returns {{ socket: WebSocket, close: function }}
 */
export function startSigner({
  relayWsUrl,
  sessionId,
  pairingSecret,
  frag = "",
  requestApproval,
  sign,
  getFingerprint,
  onStatus = () => {},
  makeSocket,
}) {
  const url =
    `${relayWsUrl}?session=${encodeURIComponent(sessionId)}` +
    `&role=signer&key=${encodeURIComponent(pairingSecret)}`;
  const ws = makeSocket ? makeSocket(url) : new WebSocket(url);

  // E2E relay channel: on pairing both peers exchange ephemeral X25519 pubkeys
  // (kex) and AES-GCM-seal every sensitive message (enc). The broker only ever
  // relays kex + enc — it cannot read the canonical payload or the signature.
  const e2e = new E2ESession(pairingSecret, frag);

  ws.onopen = () => onStatus("connected");
  ws.onclose = () => onStatus("closed");
  ws.onerror = () => onStatus("error");

  ws.onmessage = async (evt) => {
    let msg;
    try {
      msg = JSON.parse(evt.data);
    } catch {
      return;
    }
    if (msg.type === "paired") {
      onStatus("paired");
      try {
        send(await e2e.start()); // send our kex pubkey
      } catch (err) {
        onStatus("error:kex_" + err.message);
      }
      return;
    }
    if (msg.type === "kex") {
      try {
        await e2e.onKex(msg.pub);
        onStatus("secured");
      } catch (err) {
        onStatus("error:kex_" + err.message);
      }
      return;
    }
    if (msg.type === "enc") {
      try {
        const inner = await e2e.open(msg);
        if (inner.type === "sign_request") await handleSignRequest(inner);
      } catch (err) {
        onStatus("error:decrypt_" + err.message);
      }
      return;
    }
    if (msg.type === "peer_left") {
      onStatus("peer_left");
      return;
    }
    if (msg.type === "error") {
      onStatus("error:" + (msg.code || "unknown"));
      return;
    }
    if (msg.type === "sign_request") {
      // Legacy plaintext path (no E2E channel) — kept for non-E2E peers/tests.
      await handleSignRequest(msg);
    }
  };

  async function handleSignRequest(msg) {
    const { version, fields } = parseCanonical(msg.payload || "");
    // Re-derivation cross-check (anti-smuggling): rebuild the canonical V2 bytes
    // from the parsed fields and refuse to sign if they differ from what was
    // relayed. Stops a malicious desktop from getting the human to approve a
    // friendly-looking origin while signing different/extra bytes.
    if (version === "CAPAUTH_NONCE_V2" && rebuildCanonicalV2(fields) !== msg.payload) {
      await reply({ type: "reject", id: msg.id, reason: "non_canonical_payload" });
      onStatus("error:non_canonical_payload");
      return;
    }
    const approved = await requestApproval({
      id: msg.id,
      payload: msg.payload,
      origin: msg.origin || fields.origin || "",
      fingerprint: msg.fingerprint || "",
      version,
      fields,
    });
    if (!approved) {
      await reply({ type: "reject", id: msg.id, reason: "user_declined" });
      onStatus("rejected");
      return;
    }
    try {
      // Sign the EXACT relayed canonical bytes (the load-bearing contract).
      const signature = await sign(msg.payload);
      await reply({
        type: "sign_response",
        id: msg.id,
        signature,
        fingerprint: getFingerprint(),
      });
      onStatus("signed");
    } catch (err) {
      await reply({ type: "reject", id: msg.id, reason: "sign_error: " + err.message });
      onStatus("sign_error: " + err.message);
    }
  }

  // Reply over the E2E channel when secured (broker can't read it); fall back to
  // plaintext for a legacy/non-E2E peer.
  async function reply(obj) {
    send(e2e.isSecure ? await e2e.seal(obj) : obj);
  }

  function send(obj) {
    ws.send(JSON.stringify(obj));
  }

  return { socket: ws, close: () => ws.close() };
}
