import { describe, expect, it } from "vitest";
import { guessCredentialKind } from "./lib";

const TOR_KEY = "ZGBMJ4VIRNVUOQ5SJ2JXPSSWHB2R4YGTKPDGSMZ4HWCD5WLT2YKQ";

describe("guessCredentialKind", () => {
  it("recognises a Yggdrasil key", () => {
    expect(guessCredentialKind("ba83a2e554a8a087cebdb3f053468cd3ff915b5dd94bf11b7a5fc2e36f13158b")).toBe("ygg_key");
  });

  it("recognises Tor client keys, bare or as an authorized_clients line", () => {
    expect(guessCredentialKind(TOR_KEY)).toBe("tor_client_key");
    expect(guessCredentialKind(` ${TOR_KEY.toLowerCase()} `)).toBe("tor_client_key");
    expect(guessCredentialKind(`descriptor:x25519:${TOR_KEY}`)).toBe("tor_client_key");
  });

  it("falls back to an IP credential", () => {
    expect(guessCredentialKind("2001:db8::1")).toBe("ip");
    expect(guessCredentialKind("10.0.0.0/8")).toBe("ip");
    expect(guessCredentialKind(`other:${TOR_KEY}`)).toBe("ip");
  });
});
