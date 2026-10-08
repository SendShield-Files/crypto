export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function concat(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function zeroBytes(buffer: Uint8Array | ArrayBuffer | null | undefined): void {
  if (!buffer) return;
  try {
    if (buffer instanceof Uint8Array) {
      if (buffer.byteLength > 0 && !(buffer.buffer as { detached?: boolean }).detached) {
        buffer.fill(0);
      }
    } else if (buffer instanceof ArrayBuffer) {
      if (buffer.byteLength > 0 && !(buffer as { detached?: boolean }).detached) {
        new Uint8Array(buffer).fill(0);
      }
    }
  } catch {
    // Ignore detached or unfillable buffers
  }
}

