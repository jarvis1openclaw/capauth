/**
 * Tests for device-to-device key transfer over QR (keyqr.js).
 */
import { describe, it, expect } from "vitest";
import {
  KEYQR_MAGIC,
  chunkPayload,
  parseKeyFrame,
  KeyFrameCollector,
} from "../../lib/keyqr.js";

const KEY =
  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + "x".repeat(2500) + "\n-----END PGP PRIVATE KEY BLOCK-----";

describe("keyqr chunk/parse", () => {
  it("round-trips a payload through chunk → collect → assemble", () => {
    const frames = chunkPayload(KEY, 700, "ab12");
    expect(frames.length).toBeGreaterThan(1);
    expect(frames[0].startsWith(KEYQR_MAGIC + "|ab12|0|")).toBe(true);
    const col = new KeyFrameCollector();
    // feed out of order to prove index-based reassembly
    [...frames].reverse().forEach((f) => col.addRaw(f));
    expect(col.complete).toBe(true);
    expect(col.assemble()).toBe(KEY);
  });

  it("handles a single-frame (small) payload", () => {
    const frames = chunkPayload("hello", 700, "cd34");
    expect(frames.length).toBe(1);
    const col = new KeyFrameCollector();
    col.addRaw(frames[0]);
    expect(col.assemble()).toBe("hello");
  });

  it("parseKeyFrame rejects non-frames and malformed frames", () => {
    expect(parseKeyFrame("capauth-bunker://host/s?key=x")).toBeNull();
    expect(parseKeyFrame("CAPK1|id|5|3|x")).toBeNull(); // i >= n
    expect(parseKeyFrame("CAPK1|id|x|3|y")).toBeNull(); // non-int index
    expect(parseKeyFrame("")).toBeNull();
    expect(parseKeyFrame("CAPK1|id|0|2|chunk").chunk).toBe("chunk");
  });

  it("ignores frames from a different transfer", () => {
    const col = new KeyFrameCollector();
    col.addRaw("CAPK1|aaaa|0|2|first");
    expect(col.add(parseKeyFrame("CAPK1|bbbb|1|2|other"))).toBe(false);
    expect(col.complete).toBe(false);
    col.addRaw("CAPK1|aaaa|1|2|second");
    expect(col.complete).toBe(true);
    expect(col.assemble()).toBe("firstsecond");
  });

  it("preserves a chunk that itself contains the separator", () => {
    const f = parseKeyFrame("CAPK1|id|0|1|a|b|c");
    expect(f.chunk).toBe("a|b|c");
  });
});
