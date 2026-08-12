import { MAX_ATTACHMENT_PLAINTEXT_BYTES } from "@janjacord/schemas";

export const MAX_RENDERER_ATTACHMENT_BYTES = MAX_ATTACHMENT_PLAINTEXT_BYTES;

export function attachmentSizeIsAllowed(sizeBytes: number): boolean {
  return Number.isSafeInteger(sizeBytes) && sizeBytes > 0 && sizeBytes <= MAX_RENDERER_ATTACHMENT_BYTES;
}

export function encodeAttachmentBytes(buffer: ArrayBuffer): string {
  if (!attachmentSizeIsAllowed(buffer.byteLength)) throw new Error("attachment size is outside the supported range");
  const bytes = new Uint8Array(buffer);
  const segments: string[] = [];
  for (let index = 0; index < bytes.length; index += 0x8000) {
    segments.push(String.fromCharCode(...bytes.subarray(index, index + 0x8000)));
  }
  return btoa(segments.join(""));
}
