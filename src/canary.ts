import { concat, fromBase64Url, toBase64Url } from "./bytes.js";

export const VAULT_CANARY = "VALID_VAULT_KEY_2026";

export function packVaultCanary(iv: Uint8Array, ciphertext: Uint8Array): string {
  return toBase64Url(concat([iv, ciphertext]));
}

export function unpackVaultCanary(token: string): { iv: Uint8Array; ciphertext: Uint8Array } {
  const packed = fromBase64Url(token);
  if (packed.length < 28) throw new Error("That password is wrong.");
  return {
    iv: packed.subarray(0, 12),
    ciphertext: packed.subarray(12),
  };
}
