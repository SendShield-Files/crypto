import { describe, expect, it } from "vitest";
import { aesEncrypt, ciphertextByteLength, ciphertextFrameLengths, decryptPlaintext, encryptPlaintext, exportFileKey, generateFileKey, importFileKey } from "./aes.js";
import { concat, randomBytes, zeroBytes } from "./bytes.js";
import { decryptHeader, encryptHeader } from "./header.js";
import { deriveVaultKey, openVaultCanary, packVaultCanary, sealVaultCanary, unpackVaultCanary, unwrapFileKey, unwrapWithPassphrase, wrapBytes, wrapFileKey, wrapWithPassphrase } from "./kdf.js";
import { generateRequestKeyPair, sealFileKey, unsealFileKey } from "./seal.js";

describe("crypto", () => {
  it("splits ciphertext into one frame per chunk", () => {
    const frames = ciphertextFrameLengths(70, 32);
    expect(frames).toEqual([12 + 32 + 16, 12 + 32 + 16, 12 + 6 + 16]);
    expect(frames.reduce((sum, length) => sum + length, 0)).toBe(ciphertextByteLength(70, 32));
    expect(ciphertextFrameLengths(0)).toEqual([28]);
  });

  it("round-trips a file that spans more than one chunk", async () => {
    const key = await generateFileKey();
    const plain = randomBytes(70);
    const blob = await encryptPlaintext(plain, key, 32);
    const opened = await decryptPlaintext(blob, key, plain.byteLength, 32);
    expect(opened).toEqual(plain);
  });

  it("rejects a tampered chunk", async () => {
    const key = await generateFileKey();
    const blob = await encryptPlaintext(randomBytes(40), key, 32);
    blob[20] ^= 0xff;
    await expect(decryptPlaintext(blob, key, 40, 32)).rejects.toThrow();
  });

  it("rejects frames that were swapped", async () => {
    const key = await generateFileKey();
    const plain = randomBytes(64);
    const blob = await encryptPlaintext(plain, key, 32);
    const frame = 12 + 32 + 16;
    const swapped = concat([blob.subarray(frame, frame * 2), blob.subarray(0, frame)]);
    await expect(decryptPlaintext(swapped, key, plain.byteLength, 32)).rejects.toThrow();
  });

  it("rejects the wrong key", async () => {
    const blob = await encryptPlaintext(randomBytes(40), await generateFileKey(), 32);
    await expect(decryptPlaintext(blob, await generateFileKey(), 40, 32)).rejects.toThrow();
  });

  it("round-trips an empty file", async () => {
    const key = await generateFileKey();
    const blob = await encryptPlaintext(new Uint8Array(), key);
    await expect(decryptPlaintext(blob, key, 0)).resolves.toEqual(new Uint8Array());
  });

  it("rejects a frame that was sealed without chunk binding", async () => {
    const key = await generateFileKey();
    const left = randomBytes(32);
    const right = randomBytes(6);
    const first = await aesEncrypt(key, left);
    const second = await aesEncrypt(key, right);
    const blob = concat([first.iv, first.ciphertext, second.iv, second.ciphertext]);
    await expect(decryptPlaintext(blob, key, left.byteLength + right.byteLength, 32)).rejects.toThrow();
  });

  it("keeps the filename inside the encrypted header", async () => {
    const key = await generateFileKey();
    const sealed = await encryptHeader(key, { filename: "brief.pdf", mime: "application/pdf", bytes: 12 });
    const header = await decryptHeader(key, sealed.iv, sealed.ciphertext);
    expect(header.filename).toBe("brief.pdf");
  });

  it("unwraps an open-link key with the vault key and fails a bad passphrase", async () => {
    const fileKey = await generateFileKey();
    const vault = await deriveVaultKey("correct horse battery", randomBytes(16));
    const wrapped = await wrapFileKey(vault, fileKey);
    const opened = await unwrapFileKey(vault, wrapped.iv, wrapped.ciphertext);
    expect(await exportFileKey(opened)).toEqual(await exportFileKey(fileKey));

    const passphrase = await wrapWithPassphrase("share-this-phrase", fileKey);
    await expect(unwrapWithPassphrase("", passphrase.salt, passphrase.iv, passphrase.ciphertext)).rejects.toThrow();
    const fromPhrase = await unwrapWithPassphrase("share-this-phrase", passphrase.salt, passphrase.iv, passphrase.ciphertext);
    expect(await exportFileKey(fromPhrase)).toEqual(await exportFileKey(fileKey));
  });

  it("seals a file key to a request public key and rejects tampering", async () => {
    const pair = generateRequestKeyPair();
    const fileKey = randomBytes(32);
    const sealed = await sealFileKey(fileKey, pair.publicKey);
    expect(await unsealFileKey(sealed, pair.privatePkcs8)).toEqual(fileKey);
    sealed[sealed.byteLength - 1] ^= 0xff;
    await expect(unsealFileKey(sealed, pair.privatePkcs8)).rejects.toThrow();
  });

  it("opens the vault canary only with the password that sealed it", async () => {
    const salt = randomBytes(16);
    const key = await deriveVaultKey("correct horse battery", salt);
    const sealed = await sealVaultCanary(key);
    await openVaultCanary(key, sealed.iv, sealed.ciphertext);
    const packed = unpackVaultCanary(packVaultCanary(sealed.iv, sealed.ciphertext));
    await openVaultCanary(key, packed.iv, packed.ciphertext);
    const other = await deriveVaultKey("wrong password!!", salt);
    await expect(openVaultCanary(other, sealed.iv, sealed.ciphertext)).rejects.toThrow();
    const decoy = await wrapBytes(key, new TextEncoder().encode("not-the-canary"));
    await expect(openVaultCanary(key, decoy.iv, decoy.ciphertext)).rejects.toThrow("That password is wrong.");
  });

  it("rejects a low-order X25519 public key", async () => {
    await expect(sealFileKey(randomBytes(32), new Uint8Array(32))).rejects.toThrow();
  });

  it("wipes sensitive buffers with zeroBytes", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    zeroBytes(bytes);
    expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0]));

    const buffer = new Uint8Array([10, 20, 30]).buffer;
    zeroBytes(buffer);
    expect(new Uint8Array(buffer)).toEqual(new Uint8Array([0, 0, 0]));

    // Null/undefined safety
    expect(() => zeroBytes(null)).not.toThrow();
    expect(() => zeroBytes(undefined)).not.toThrow();
  });
});
