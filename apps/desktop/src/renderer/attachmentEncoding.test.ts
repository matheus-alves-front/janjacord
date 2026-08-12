import { describe, expect, it } from "vitest";
import { attachmentSizeIsAllowed, encodeAttachmentBytes } from "./attachmentEncoding";

describe("renderer attachment encoding", () => {
  it("encodes bounded bytes canonically", () => {
    const bytes = Uint8Array.from([0, 1, 2, 253, 254, 255]);
    expect(encodeAttachmentBytes(bytes.buffer)).toBe("AAEC/f7/");
  });

  it("rejects empty and oversized sizes before reading/encoding", () => {
    expect(attachmentSizeIsAllowed(0)).toBe(false);
    expect(attachmentSizeIsAllowed(50 * 1024 * 1024)).toBe(false);
    expect(() => encodeAttachmentBytes(new ArrayBuffer(0))).toThrow(/size/);
  });
});
