import { describe, expect, it } from "vitest";
import { parseRange, scopeLabel, withRange } from "./lib";

describe("scopes and port ranges", () => {
  it("names the rows of an app", () => {
    const groups = [{ id: "sg1", label: "passive", ports: [], apps: [], created_at: "" }];
    expect(scopeLabel({ kind: "all" })).toBe("All ports");
    expect(scopeLabel({ kind: "port", port: 443, proto: "tcp" })).toBe("443/tcp");
    expect(scopeLabel({ kind: "group", id: "sg1" }, groups)).toBe("passive");
  });

  it("parses a port, a range and rejects the rest", () => {
    expect(parseRange("80/tcp")).toEqual({ start: 80, end: 80, proto: "tcp" });
    expect(parseRange("50000 - 51000/UDP")).toEqual({ start: 50000, end: 51000, proto: "udp" });
    for (const bad of ["80", "80/icmp", "0/tcp", "70000/tcp", "9-1/tcp", "a/tcp"]) expect(typeof parseRange(bad)).toBe("string");
  });

  it("keeps ranges sorted and once", () => {
    const a = { start: 80, end: 80, proto: "tcp" as const };
    const b = { start: 53, end: 53, proto: "udp" as const };
    expect(withRange(withRange([a], b), a)).toEqual([a, b]);
  });
});
