import { describe, expect, it } from "vitest";
import { solveMemoryHardPoW, verifyMemoryHardPoW } from "./pow.js";

describe("Memory-Hard Proof of Work (Argon2id)", () => {
  it("solves and verifies a memory-hard challenge with difficulty 4", async () => {
    const seed = "test-session-challenge-42";
    const salt = "salt-xyz-888";
    const canvasFingerprint = "canvas-hash-abc12345";
    const difficulty = 4;
    const memoryCost = 1024; // 1MB in tests for fast execution

    const solution = await solveMemoryHardPoW({
      seed,
      salt,
      difficulty,
      memoryCost,
      canvasFingerprint,
    });

    expect(solution.nonce).toBeGreaterThanOrEqual(0);
    expect(solution.durationMs).toBeGreaterThan(0);

    const valid = await verifyMemoryHardPoW(
      seed,
      salt,
      solution.nonce,
      difficulty,
      memoryCost,
      canvasFingerprint,
    );
    expect(valid).toBe(true);
  });

  it("fails verification if nonce is wrong or tampered", async () => {
    const seed = "test-tamper-check";
    const salt = "salt-check-999";
    const difficulty = 4;
    const memoryCost = 1024;

    const solution = await solveMemoryHardPoW({
      seed,
      salt,
      difficulty,
      memoryCost,
    });

    const invalid = await verifyMemoryHardPoW(
      seed,
      salt,
      solution.nonce + 9999, // tampered nonce
      difficulty,
      memoryCost,
    );
    expect(invalid).toBe(false);
  });

  it("fails verification if canvas fingerprint does not match", async () => {
    const seed = "test-canvas-binding";
    const salt = "salt-canvas-binding";
    const difficulty = 4;
    const memoryCost = 1024;

    const solution = await solveMemoryHardPoW({
      seed,
      salt,
      difficulty,
      memoryCost,
      canvasFingerprint: "browser-real-canvas-hash",
    });

    const tampered = await verifyMemoryHardPoW(
      seed,
      salt,
      solution.nonce,
      difficulty,
      memoryCost,
      "fake-or-missing-canvas-hash",
    );
    expect(tampered).toBe(false);
  });
});
