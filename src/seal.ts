import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { aesDecrypt, aesEncrypt, importAesKey } from "./aes.js";
import { concat, randomBytes } from "./bytes.js";

const INFO = new TextEncoder().encode("sealdrop-seal-v1");
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

export function rawPrivateToPkcs8(raw: Uint8Array): Uint8Array {
  if (raw.byteLength !== 32) throw new Error("X25519 private key must be 32 bytes");
  return concat([PKCS8_PREFIX, raw]);
}

export function pkcs8ToRawPrivate(pkcs8: Uint8Array): Uint8Array {
  if (pkcs8.byteLength !== 48 || !PKCS8_PREFIX.every((byte, index) => pkcs8[index] === byte)) {
    throw new Error("secret key is not an X25519 PKCS8 key");
  }
  return pkcs8.subarray(16);
}

export function generateRequestKeyPair(): { publicKey: Uint8Array; privatePkcs8: Uint8Array } {
  const secret = randomBytes(32);
  return { publicKey: x25519.getPublicKey(secret), privatePkcs8: rawPrivateToPkcs8(secret) };
}

export async function sealFileKey(fileKeyRaw: Uint8Array, recipientPublic: Uint8Array): Promise<Uint8Array> {
  if (recipientPublic.byteLength !== 32) throw new Error("recipient public key must be 32 bytes");
  const ephemeral = randomBytes(32);
  const ephemeralPublic = x25519.getPublicKey(ephemeral);
  const shared = x25519.getSharedSecret(ephemeral, recipientPublic);
  const wrapping = await importAesKey(hkdf(sha256, shared, ephemeralPublic, INFO, 32), ["encrypt"]);
  const { iv, ciphertext } = await aesEncrypt(wrapping, fileKeyRaw);
  return concat([ephemeralPublic, iv, ciphertext]);
}

export async function unsealFileKey(sealed: Uint8Array, recipientPrivatePkcs8: Uint8Array): Promise<Uint8Array> {
  if (sealed.byteLength < 32 + 12 + 16) throw new Error("sealed key is truncated");
  const secret = pkcs8ToRawPrivate(recipientPrivatePkcs8);
  const ephemeralPublic = sealed.subarray(0, 32);
  const shared = x25519.getSharedSecret(secret, ephemeralPublic);
  const wrapping = await importAesKey(hkdf(sha256, shared, ephemeralPublic, INFO, 32), ["decrypt"]);
  return aesDecrypt(wrapping, sealed.subarray(32, 44), sealed.subarray(44));
}
