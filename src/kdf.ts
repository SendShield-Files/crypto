import { argon2id } from "hash-wasm";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { concat, fromBase64Url, randomBytes, toBase64Url, zeroBytes } from "./bytes.js";
import { aesDecrypt, aesEncrypt, exportFileKey, importAesKey, importFileKey } from "./aes.js";

export const ARGON = {
  memorySize: 19 * 1024,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
} as const;

async function stretch(secret: string, salt: Uint8Array): Promise<Uint8Array> {
  const hash = await argon2id({
    password: secret,
    salt,
    parallelism: ARGON.parallelism,
    iterations: ARGON.iterations,
    memorySize: ARGON.memorySize,
    hashLength: ARGON.hashLength,
    outputType: "binary",
  });
  return new Uint8Array(hash);
}

export async function deriveVaultBytes(password: string, salt: Uint8Array): Promise<Uint8Array> {
  return stretch(password, salt);
}

export async function importVaultKey(raw: Uint8Array): Promise<CryptoKey> {
  return importAesKey(raw, ["encrypt", "decrypt"]);
}

export async function deriveVaultKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const raw = await deriveVaultBytes(password, salt);
  try {
    return await importVaultKey(raw);
  } finally {
    zeroBytes(raw);
  }
}

export const VAULT_CANARY = "VALID_VAULT_KEY_2026";

export async function sealVaultCanary(key: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  return wrapBytes(key, new TextEncoder().encode(VAULT_CANARY));
}

export async function openVaultCanary(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<void> {
  const plain = new TextDecoder().decode(await unwrapBytes(key, iv, ciphertext));
  if (plain !== VAULT_CANARY) throw new Error("That password is wrong.");
}

export function packVaultCanary(iv: Uint8Array, ciphertext: Uint8Array): string {
  return toBase64Url(concat([iv, ciphertext]));
}

export function unpackVaultCanary(token: string): { iv: Uint8Array; ciphertext: Uint8Array } {
  const packed = fromBase64Url(token);
  if (packed.byteLength < 28) throw new Error("That password is wrong.");
  return { iv: packed.subarray(0, 12), ciphertext: packed.subarray(12) };
}

export async function wrapBytes(key: CryptoKey, plain: Uint8Array): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  return aesEncrypt(key, plain);
}

export async function unwrapBytes(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  return aesDecrypt(key, iv, ciphertext);
}

export async function wrapFileKey(key: CryptoKey, fileKey: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const raw = await exportFileKey(fileKey);
  try {
    return await wrapBytes(key, raw);
  } finally {
    zeroBytes(raw);
  }
}

export async function unwrapFileKey(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<CryptoKey> {
  const raw = await unwrapBytes(key, iv, ciphertext);
  try {
    return await importFileKey(raw);
  } finally {
    zeroBytes(raw);
  }
}

const PASSPHRASE_V2_INFO = new TextEncoder().encode("ssf-passphrase-v2");

export async function wrapWithPassphrase(
  passphrase: string,
  fileKey: CryptoKey,
  linkKeyBytes?: Uint8Array,
) {
  const salt = randomBytes(16);
  if (linkKeyBytes) {
    if (linkKeyBytes.byteLength !== 32) throw new Error("linkKeyBytes must be 32 bytes (256 bits)");
    const argonBytes = await deriveVaultBytes(passphrase, salt);
    const ikm = concat([linkKeyBytes, argonBytes]);
    const derivedKeyBytes = hkdf(sha256, ikm, salt, PASSPHRASE_V2_INFO, 32);
    zeroBytes(argonBytes);
    zeroBytes(ikm);
    let wrapping: CryptoKey;
    try {
      wrapping = await importVaultKey(derivedKeyBytes);
    } finally {
      zeroBytes(derivedKeyBytes);
    }
    const wrapped = await wrapFileKey(wrapping, fileKey);
    return {
      salt,
      iv: wrapped.iv,
      ciphertext: wrapped.ciphertext,
      params: { ...ARGON, v: 2 },
    };
  }

  const wrapping = await deriveVaultKey(passphrase, salt);
  const wrapped = await wrapFileKey(wrapping, fileKey);
  return {
    salt,
    iv: wrapped.iv,
    ciphertext: wrapped.ciphertext,
    params: { ...ARGON, v: 1 },
  };
}

export async function unwrapWithPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  linkKeyBytes?: Uint8Array,
  v = 1,
): Promise<CryptoKey> {
  if (v === 2) {
    if (!linkKeyBytes || linkKeyBytes.byteLength !== 32) {
      throw new Error("A 256-bit link key is required to unlock this transfer.");
    }
    const argonBytes = await deriveVaultBytes(passphrase, salt);
    const ikm = concat([linkKeyBytes, argonBytes]);
    const derivedKeyBytes = hkdf(sha256, ikm, salt, PASSPHRASE_V2_INFO, 32);
    zeroBytes(argonBytes);
    zeroBytes(ikm);
    let wrapping: CryptoKey;
    try {
      wrapping = await importVaultKey(derivedKeyBytes);
    } finally {
      zeroBytes(derivedKeyBytes);
    }
    return unwrapFileKey(wrapping, iv, ciphertext);
  }

  const wrapping = await deriveVaultKey(passphrase, salt);
  return unwrapFileKey(wrapping, iv, ciphertext);
}
