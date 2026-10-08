import { describe, expect, it } from "vitest";
import { solveProofOfWork, verifyProofOfWork } from "./pow.js";

describe("Proof of Work", () => {
  it("solves and verifies a challenge correctly", async () => {
    const seed = "test-transfer-seed-12345";
    const difficulty = 12; // 12 bits for instant test run
    const result = await solveProofOfWork(seed, difficulty);
    expect(result.nonce).toBeGreaterThanOrEqual(0);
    const isValid = await verifyProofOfWork(seed, result.nonce, difficulty);
    expect(isValid).toBe(true);

    const isDifferentSeedValid = await verifyProofOfWork("different-seed", result.nonce, 16);
    expect(isDifferentSeedValid).toBe(false);
  });
});
