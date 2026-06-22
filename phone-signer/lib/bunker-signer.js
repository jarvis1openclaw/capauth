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

import { parseCanonical } from "./canonical.js";

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
      await handleSignRequest(msg);
    }
  };

  async function handleSignRequest(msg) {
    const { version, fields } = parseCanonical(msg.payload || "");
    const approved = await requestApproval({
      id: msg.id,
      payload: msg.payload,
      origin: msg.origin || fields.origin || "",
      fingerprint: msg.fingerprint || "",
      version,
      fields,
    });
    if (!approved) {
      send({ type: "reject", id: msg.id, reason: "user_declined" });
      onStatus("rejected");
      return;
    }
    try {
      // Sign the EXACT relayed canonical bytes (the load-bearing contract).
      const signature = await sign(msg.payload);
      send({
        type: "sign_response",
        id: msg.id,
        signature,
        fingerprint: getFingerprint(),
      });
      onStatus("signed");
    } catch (err) {
      send({ type: "reject", id: msg.id, reason: "sign_error: " + err.message });
      onStatus("sign_error");
    }
  }

  function send(obj) {
    ws.send(JSON.stringify(obj));
  }

  return { socket: ws, close: () => ws.close() };
}
