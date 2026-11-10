import { describe, expect, it } from "vitest";
import { buildColumns, buildRows, cellOf, type Ctx } from "./matrix";
import { grantView, mkApp, mkGroup, mkPeer, mkTag, networks } from "./test/helpers";

const alice = mkPeer("p1", "alice", { groups: ["g1"] });
const bob = mkPeer("p2", "bob");
const team = mkGroup("g1", "team", ["p1"]);
const web = mkTag("t1", "web", ["a1"]);
const apps = [mkApp("a1", "nginx", [80, 443])];

const ctx = (grants: ReturnType<typeof grantView>[], scope: string | null = null): Ctx => ({
  grants, tags: [web], peers: [alice, bob], groups: [team], networks, scope,
});

const [tagRow, appRow, portRow] = buildRows(apps, [web], new Set(["a1"]));
const col = (key: string, c: Ctx) => buildColumns(c).find((x) => x.key === key)!;

describe("the overview's rows and columns", () => {
  it("rows are tags, then apps, then the ports of the expanded apps", () => {
    expect([tagRow.kind, appRow.kind, portRow.kind]).toEqual(["tag", "app", "port"]);
    expect(buildRows(apps, [web], new Set()).map((r) => r.kind)).toEqual(["tag", "app"]);
  });

  it("columns are groups, peers, Anyone and Everyone on each LAN, the last only without a network scope", () => {
    const c = ctx([]);
    expect(buildColumns(c).map((x) => x.label)).toEqual(["group team", "alice", "bob", "Anyone", "Everyone on LAN"]);
    expect(buildColumns({ ...c, scope: "n-ygg" }).map((x) => x.label)).toEqual(["group team", "alice", "bob", "Anyone"]);
  });
});

describe("what a cell shows", () => {
  it("granted: a grant on every network", () => {
    const c = ctx([grantView({ subject: { kind: "peer", id: "p2" } })]);
    expect(cellOf(appRow, col("peer:p2", c), c).state).toBe("granted");
  });

  it("partial: a grant on some networks only, with the networks named", () => {
    const c = ctx([grantView({ subject: { kind: "peer", id: "p2" }, network_id: "n-lan" })]);
    const cell = cellOf(appRow, col("peer:p2", c), c);
    expect(cell.state).toBe("partial");
    expect(cell.networkIds).toEqual(["n-lan"]);
  });

  it("inherited: through a group, a tag, or the whole app for its ports; the origin is named", () => {
    const viaGroup = ctx([grantView({ subject: { kind: "group", id: "g1" } })]);
    expect(cellOf(appRow, col("peer:p1", viaGroup), viaGroup)).toMatchObject({ state: "inherited", origin: { kind: "group", label: "team" } });

    const viaTag = ctx([grantView({ target: { kind: "tag", id: "t1" }, subject: { kind: "peer", id: "p2" } })]);
    expect(cellOf(appRow, col("peer:p2", viaTag), viaTag)).toMatchObject({ state: "inherited", origin: { kind: "tag", label: "web" } });

    const whole = ctx([grantView({ subject: { kind: "peer", id: "p2" } })]);
    expect(cellOf(portRow, col("peer:p2", whole), whole)).toMatchObject({ state: "inherited", origin: { kind: "app" } });
  });

  it("none: nothing reaches", () => {
    const c = ctx([grantView({ subject: { kind: "peer", id: "p2" } })]);
    expect(cellOf(appRow, col("peer:p1", c), c).state).toBe("none");
    expect(cellOf(tagRow, col("peer:p2", c), c).state).toBe("none");
  });

  it("a network scope shows what holds on that network, and a grant on all networks as granted", () => {
    const grants = [
      grantView({ id: "g-lan", subject: { kind: "peer", id: "p1" }, network_id: "n-lan" }),
      grantView({ id: "g-all", subject: { kind: "peer", id: "p2" }, network_id: null }),
    ];
    const lan = ctx(grants, "n-lan");
    expect(cellOf(appRow, col("peer:p1", lan), lan).state).toBe("granted");
    expect(cellOf(appRow, col("peer:p2", lan), lan)).toMatchObject({ state: "granted", allNetworks: true });
    const ygg = ctx(grants, "n-ygg");
    expect(cellOf(appRow, col("peer:p1", ygg), ygg).state).toBe("none");
  });

  it("the Everyone-on-LAN column takes the LAN grants to Anyone, the Anyone column the rest", () => {
    const c = ctx([grantView({ id: "g1", subject: { kind: "anyone" }, network_id: "n-lan" }), grantView({ id: "g2", target: { kind: "app", id: "a9" }, subject: { kind: "anyone" } })]);
    expect(cellOf(appRow, col("segment:n-lan", c), c).state).toBe("granted");
    expect(cellOf(appRow, col("anyone", c), c).state).toBe("none");
  });
});
