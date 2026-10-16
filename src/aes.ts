import { concat, randomBytes } from "./bytes.js";

export const CHUNK_BYTES = 16 * 1024 * 1024;
const CHUNK_AAD_PREFIX = new TextEncoder().encode("sealdrop-chunk-v1");

function source(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function chunkAdditionalData(index: number): Uint8Array {
  const out = new Uint8Array(CHUNK_AAD_PREFIX.length + 4);
  out.set(CHUNK_AAD_PREFIX, 0);
  new DataView(out.buffer).setUint32(CHUNK_AAD_PREFIX.length, index, false);
  return out;
}

export async function importAesKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", source(raw), "AES-GCM", false, usages);
}

export async function generateFileKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export async function exportFileKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

export async function importFileKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", source(raw), "AES-GCM", true, ["encrypt", "decrypt"]);
}

export async function aesEncrypt(
  key: CryptoKey,
  plain: Uint8Array,
  additionalData?: Uint8Array,
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = randomBytes(12);
  const params: AesGcmParams = { name: "AES-GCM", iv: source(iv) };
  if (additionalData) params.additionalData = source(additionalData);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(params, key, source(plain)));
  return { iv, ciphertext };
}

export async function aesDecrypt(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  additionalData?: Uint8Array,
): Promise<Uint8Array> {
  const params: AesGcmParams = { name: "AES-GCM", iv: source(iv) };
  if (additionalData) params.additionalData = source(additionalData);
  const plain = await crypto.subtle.decrypt(params, key, source(ciphertext));
  return new Uint8Array(plain);
}

export function ciphertextByteLength(plainBytes: number, chunkBytes = CHUNK_BYTES): number {
  return ciphertextFrameLengths(plainBytes, chunkBytes).reduce((sum, length) => sum + length, 0);
}

export function ciphertextFrameLengths(plainBytes: number, chunkBytes = CHUNK_BYTES): number[] {
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes <= 0) throw new Error("chunkBytes must be positive");
  if (!Number.isSafeInteger(plainBytes) || plainBytes < 0) throw new Error("plainBytes must be non-negative");
  if (plainBytes === 0) return [28];
  const lengths: number[] = [];
  for (let written = 0; written < plainBytes; written += chunkBytes) {
    const size = Math.min(chunkBytes, plainBytes - written);
    lengths.push(12 + size + 16);
  }
  return lengths;
}

async function encryptChunk(key: CryptoKey, plain: Uint8Array, index: number): Promise<Uint8Array> {
  const { iv, ciphertext } = await aesEncrypt(key, plain, chunkAdditionalData(index));
  return concat([iv, ciphertext]);
}

async function decryptChunk(key: CryptoKey, frame: Uint8Array, index: number): Promise<Uint8Array> {
  return aesDecrypt(key, frame.subarray(0, 12), frame.subarray(12), chunkAdditionalData(index));
}

export async function encryptPlaintext(
  plain: Uint8Array,
  key: CryptoKey,
  chunkBytes = CHUNK_BYTES,
  firstIndex = 0,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes <= 0) throw new Error("chunkBytes must be positive");
  if (plain.byteLength === 0) return encryptChunk(key, plain, firstIndex);
  const parts: Uint8Array[] = [];
  for (let offset = 0, index = firstIndex; offset < plain.byteLength; offset += chunkBytes, index += 1) {
    parts.push(await encryptChunk(key, plain.subarray(offset, Math.min(offset + chunkBytes, plain.byteLength)), index));
  }
  return concat(parts);
}

export async function decryptPlaintext(
  blob: Uint8Array,
  key: CryptoKey,
  plainBytes: number,
  chunkBytes = CHUNK_BYTES,
  firstIndex = 0,
): Promise<Uint8Array> {
  const expectedCipherBytes = ciphertextByteLength(plainBytes, chunkBytes);
  if (blob.byteLength < expectedCipherBytes) throw new Error("truncated ciphertext");
  if (blob.byteLength > expectedCipherBytes) throw new Error("unexpected ciphertext length");
  const out = new Uint8Array(plainBytes);
  let read = 0;
  let written = 0;
  const chunks = Math.max(1, Math.ceil(plainBytes / chunkBytes));
  for (let index = 0; index < chunks; index += 1) {
    const size = plainBytes === 0 ? 0 : Math.min(chunkBytes, plainBytes - written);
    const frame = blob.subarray(read, read + 12 + size + 16);
    if (frame.byteLength !== 12 + size + 16) throw new Error("truncated ciphertext");
    const plain = await decryptChunk(key, frame, firstIndex + index);
    out.set(plain, written);
    read += frame.byteLength;
    written += size;
  }
  if (read !== blob.byteLength) throw new Error("unexpected ciphertext length");
  return out;
}

export function encryptStream(file: Blob, key: CryptoKey, chunkBytes = CHUNK_BYTES): ReadableStream<Uint8Array> {
  let offset = 0;
  let index = 0;
  let emittedEmpty = false;
  return new ReadableStream({
    async pull(controller) {
      if (file.size === 0) {
        if (emittedEmpty) {
          controller.close();
          return;
        }
        emittedEmpty = true;
        controller.enqueue(await encryptChunk(key, new Uint8Array(), 0));
        controller.close();
        return;
      }
      if (offset >= file.size) {
        controller.close();
        return;
      }
      const end = Math.min(offset + chunkBytes, file.size);
      const plain = new Uint8Array(await file.slice(offset, end).arrayBuffer());
      controller.enqueue(await encryptChunk(key, plain, index));
      offset = end;
      index += 1;
      if (offset >= file.size) controller.close();
    },
  });
}
