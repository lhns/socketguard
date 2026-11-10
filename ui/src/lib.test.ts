import { describe, expect, it } from "vitest";
import type { ParsedCredential } from "./api";
import { CREDENTIAL_EXAMPLES } from "./generated/credentialExamples";
import { CREDENTIAL_PLACEHOLDER, credentialsFromParsed } from "./lib";

const ok = (input: string, normalized: string): ParsedCredential => ({
  input, kind: "ip", normalized, reach: [], error: null,
});

describe("credentialsFromParsed", () => {
  it("sends the daemon's kind and normalized value", () => {
    expect(credentialsFromParsed([ok("10.0.0.7", "10.0.0.7/32")])).toEqual({
      credentials: [{ kind: "ip", value: "10.0.0.7/32", label: null }],
    });
  });

  it("reports the first error, or nothing to add", () => {
    const bad: ParsedCredential = { input: "200::", kind: "ygg_addr", normalized: null, reach: [], error: "not a node" };
    expect(credentialsFromParsed([ok("a", "a"), bad])).toEqual({ error: "200::: not a node" });
    expect(credentialsFromParsed([])).toHaveProperty("error");
  });
});

describe("credential examples", () => {
  it("come from the daemon's core crate and include IPv4", () => {
    expect(CREDENTIAL_EXAMPLES.some((e) => e.kind === "ip" && e.value.includes("."))).toBe(true);
    expect(CREDENTIAL_PLACEHOLDER).toContain(CREDENTIAL_EXAMPLES.find((e) => e.kind === "ygg_addr")!.value);
  });
});
