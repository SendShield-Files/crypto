import { aesDecrypt, aesEncrypt, decryptPlaintext, encryptPlaintext } from "./aes.js";
import { fromBase64Url, toBase64Url } from "./bytes.js";

export type FileHeader = {
  filename: string;
  mime: string;
  bytes: number;
  consumeSecret?: string;
  sha256?: string;
  note?: string;
  manifest?: { name: string; bytes: number }[];
  viewOnce?: boolean;
  watermark?: boolean;
  watermarkLabel?: string;
  secretMode?: boolean;
  title?: string;
};

export async function encryptHeader(key: CryptoKey, header: FileHeader) {
  const plain = new TextEncoder().encode(JSON.stringify(header));
  return aesEncrypt(key, plain);
}

export async function decryptHeader(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array): Promise<FileHeader> {
  const json = new TextDecoder().decode(await aesDecrypt(key, iv, ciphertext));
  const header = JSON.parse(json) as FileHeader | null;
  if (
    !header ||
    typeof header !== "object" ||
    typeof header.filename !== "string" ||
    !Number.isSafeInteger(header.bytes) ||
    header.bytes < 0
  ) {
    throw new Error("header is not a file header");
  }
  return header;
}

export async function encryptFileBytes(plain: Uint8Array, key: CryptoKey, chunkBytes?: number) {
  return encryptPlaintext(plain, key, chunkBytes);
}

export async function decryptFileBytes(blob: Uint8Array, key: CryptoKey, plainBytes: number, chunkBytes?: number) {
  return decryptPlaintext(blob, key, plainBytes, chunkBytes);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
}

export async function sha256Hex(bytes: BufferSource): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function consumeSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export function consumeSecretBytes(secret: string): Uint8Array {
  return fromBase64Url(secret);
}
