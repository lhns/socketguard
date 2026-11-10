import { describe, expect, it } from "vitest";
import { appEntries, appEntriesFromGrants, mergeEntries, subjectEntries, type NameCtx } from "./access";
import type { EffectiveAccess } from "./api";
import { grantView, mkApp, mkGroup, mkPeer, mkTag, networks } from "./test/helpers";

const alice = mkPeer("p1", "alice", { groups: ["g1"] });
const team = mkGroup("g1", "team", ["p1"]);
const web = mkTag("t1", "web", ["a1", "a2"]);
const ctx: NameCtx = { apps: [mkApp("a1", "nginx", [80, 443]), mkApp("a2", "redis", [6379])], tags: [web], peers: [alice], groups: [team], networks };

const direct = grantView({ id: "g-direct", subject: { kind: "peer", id: "p1" } });
const port80 = grantView({ id: "g-80", port: { port: 80, proto: "tcp" }, subject: { kind: "peer", id: "p1" } });
const viaTag = grantView({ id: "g-tag", target: { kind: "tag", id: "t1" }, subject: { kind: "anyone" }, network_id: "n-lan" });
const toGroup = grantView({ id: "g-team", target: { kind: "app", id: "a2" }, subject: { kind: "group", id: "g1" } });

describe("appEntries", () => {
  const access: EffectiveAccess[] = [
    { grant_id: "g-80", port: { port: 80, proto: "tcp" }, network_id: null, subject: { kind: "peer", id: "p1" }, origin: { kind: "direct" } },
    { grant_id: "g-tag", port: null, network_id: "n-lan", subject: { kind: "anyone" }, origin: { kind: "tag", tag_id: "t1" } },
    // The same grant reaching the app through two ports of a tag member is one entry per port.
    { grant_id: "g-tag", port: null, network_id: "n-lan", subject: { kind: "anyone" }, origin: { kind: "tag", tag_id: "t1" } },
    { grant_id: "g-direct", port: null, network_id: null, subject: { kind: "peer", id: "p1" }, origin: { kind: "direct" } },
  ];

  it("lists each access once, whole-app access first and per-port extras after", () => {
    const entries = appEntries(access, [direct, port80, viaTag], ctx);
    expect(entries.map((e) => [e.name, e.port?.port ?? null])).toEqual([
      ["alice", null],
      ["Everyone on LAN", null],
      ["alice", 80],
    ]);
  });

  it("a direct grant can be revoked; one through a tag links to the tag", () => {
    const entries = appEntries(access, [direct, port80, viaTag], ctx);
    const lan = entries.find((e) => e.name === "Everyone on LAN")!;
    expect(lan.origin).toEqual({ kind: "tag", id: "t1", label: "web" });
    expect(lan.grants).toEqual([]);
    expect(entries.find((e) => e.port === null && e.name === "alice")!.grants.map((g) => g.id)).toEqual(["g-direct"]);
  });

  it("a grant on the app to a group is direct, so it can be revoked there", () => {
    const [entry] = appEntries(
      [{ grant_id: "g-team", port: null, network_id: null, subject: { kind: "group", id: "g1" }, origin: { kind: "group", group_id: "g1" } }],
      [toGroup], ctx,
    );
    expect(entry.name).toBe("group team");
    expect(entry.origin).toEqual({ kind: "direct" });
    expect(entry.grants).toHaveLength(1);
  });
});

describe("subjectEntries", () => {
  it("lists what a peer reaches, with the grants of its groups marked as inherited", () => {
    const entries = subjectEntries({ kind: "peer", id: "p1" }, null, [direct, toGroup], ctx);
    expect(entries.map((e) => [e.name, e.origin.kind])).toEqual([["nginx", "direct"], ["redis", "group"]]);
    expect(entries[1].grants).toEqual([]);
    expect(entries[1].origin).toMatchObject({ id: "g1", label: "team" });
  });

  it("Anyone and a segment are told apart by the network", () => {
    const everywhere = grantView({ id: "g-all", subject: { kind: "anyone" } });
    expect(subjectEntries({ kind: "anyone" }, null, [everywhere, viaTag], ctx).map((e) => e.key)).toEqual(["g-all"]);
    expect(subjectEntries({ kind: "anyone" }, "n-lan", [everywhere, viaTag], ctx).map((e) => e.key)).toEqual(["g-tag"]);
  });
});

describe("mergeEntries", () => {
  it("counts how many of the selected things have each access", () => {
    const one = appEntriesFromGrants("a1", [direct, viaTag], ctx);
    const two = appEntriesFromGrants("a2", [viaTag], ctx);
    const merged = mergeEntries([one, two]);
    const lan = merged.find((e) => e.name === "Everyone on LAN")!;
    const alice = merged.find((e) => e.name === "alice")!;
    expect([lan.have, lan.of]).toEqual([2, 2]);
    expect([alice.have, alice.of]).toEqual([1, 2]);
    expect(alice.grants.map((g) => g.id)).toEqual(["g-direct"]);
  });

  it("collects every grant behind an access that several things share, so one Revoke removes them all", () => {
    const g2 = grantView({ id: "g-direct-2", target: { kind: "app", id: "a2" }, subject: { kind: "peer", id: "p1" } });
    const merged = mergeEntries([appEntriesFromGrants("a1", [direct, g2], ctx), appEntriesFromGrants("a2", [direct, g2], ctx)]);
    expect(merged).toHaveLength(1);
    expect(merged[0].have).toBe(2);
    expect(merged[0].grants.map((g) => g.id)).toEqual(["g-direct", "g-direct-2"]);
  });
});
