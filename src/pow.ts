import { argon2id } from "hash-wasm";

/**
 * Proof-of-work puzzles that raise the cost of automated abuse.
 * They do not encrypt files and they are not part of confidentiality.
 * Callers choose the difficulty. A higher cost slows repeated requests.
 */

function hasLeadingZeroBits(bytes: Uint8Array, bits: number): boolean {
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > bytes.length * 8) return false;
  const fullBytes = Math.floor(bits / 8);
  const remainingBits = bits % 8;

  for (let i = 0; i < fullBytes; i++) {
    if (bytes[i] !== 0) return false;
  }

  if (remainingBits > 0) {
    const mask = (0xff << (8 - remainingBits)) & 0xff;
    if ((bytes[fullBytes] & mask) !== 0) return false;
  }

  return true;
}

export type MemoryHardPoWOptions = {
  seed: string;
  salt: string;
  difficulty: number;
  memoryCost?: number; // KiB, defaults to 16384 (16MB)
  canvasFingerprint?: string;
  onProgress?: (attempts: number) => void;
};

export type MemoryHardPoWSolution = {
  nonce: number;
  durationMs: number;
};

/**
 * Solves an Argon2id cost puzzle. The memory cost is chosen by the caller.
 */
export async function solveMemoryHardPoW(
  options: MemoryHardPoWOptions,
): Promise<MemoryHardPoWSolution> {
  const {
    seed,
    salt,
    difficulty,
    memoryCost = 16 * 1024,
    canvasFingerprint = "",
    onProgress,
  } = options;

  const start = performance.now();
  const encoder = new TextEncoder();
  const saltBytes = encoder.encode(salt);
  let nonce = 0;

  while (true) {
    const password = `${seed}:${canvasFingerprint}:${nonce}`;
    const hash = await argon2id({
      password,
      salt: saltBytes,
      parallelism: 1,
      iterations: 1,
      memorySize: memoryCost,
      hashLength: 32,
      outputType: "binary",
    });

    if (hasLeadingZeroBits(new Uint8Array(hash), difficulty)) {
      return {
        nonce,
        durationMs: Math.round(performance.now() - start),
      };
    }

    nonce++;
    if (onProgress && nonce % 5 === 0) {
      onProgress(nonce);
    }

    // Yield to the event loop every 4 iterations to keep browser UI smooth
    if (nonce % 4 === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}

/**
 * Checks one Argon2id puzzle solution. The caller supplies the same cost the solver used.
 */
export async function verifyMemoryHardPoW(
  seed: string,
  salt: string,
  nonce: number,
  difficulty: number,
  memoryCost = 16 * 1024,
  canvasFingerprint = "",
): Promise<boolean> {
  const encoder = new TextEncoder();
  const saltBytes = encoder.encode(salt);
  const password = `${seed}:${canvasFingerprint}:${nonce}`;

  const hash = await argon2id({
    password,
    salt: saltBytes,
    parallelism: 1,
    iterations: 1,
    memorySize: memoryCost,
    hashLength: 32,
    outputType: "binary",
  });

  return hasLeadingZeroBits(new Uint8Array(hash), difficulty);
}

/**
 * Solves a lightweight Proof-of-Work challenge (SHA-256 Hashcash).
 */
export async function solveProofOfWork(
  seed: string,
  difficultyBits = 16,
  onProgress?: (attempts: number) => void,
): Promise<{ nonce: number; durationMs: number }> {
  const start = performance.now();
  const encoder = new TextEncoder();
  let nonce = 0;
  const BATCH_SIZE = 1000;

  while (true) {
    for (let i = 0; i < BATCH_SIZE; i++) {
      const data = encoder.encode(`${seed}:${nonce}`);
      const digest = await crypto.subtle.digest("SHA-256", data);
      const bytes = new Uint8Array(digest);

      if (hasLeadingZeroBits(bytes, difficultyBits)) {
        return {
          nonce,
          durationMs: Math.round(performance.now() - start),
        };
      }
      nonce++;
    }

    if (onProgress) {
      onProgress(nonce);
    }

    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/**
 * Verifies that a nonce satisfies the SHA-256 PoW difficulty for a seed.
 */
export async function verifyProofOfWork(
  seed: string,
  nonce: number,
  difficultyBits = 16,
): Promise<boolean> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${seed}:${nonce}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  return hasLeadingZeroBits(bytes, difficultyBits);
}
