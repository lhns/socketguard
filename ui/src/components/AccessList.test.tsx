import { describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { appEntries, subjectEntries, type NameCtx } from "../access";
import type { EffectiveAccess } from "../api";
import { grantView, mkApp, mkGroup, mkPeer, mkTag, networks, renderWithProviders } from "../test/helpers";
import AccessList from "./AccessList";

const alice = mkPeer("p1", "alice", { groups: ["g1"] });
const team = mkGroup("g1", "team", ["p1"]);
const web = mkTag("t1", "web", ["a1"]);
const ctx: NameCtx = { apps: [mkApp("a1", "nginx", [80]), mkApp("a2", "redis", [6379])], tags: [web], peers: [alice], groups: [team], networks };

const direct = grantView({ id: "g-direct", subject: { kind: "peer", id: "p1" }, scope: { kind: "port", port: 80, proto: "tcp" } });
const viaTag = grantView({ id: "g-tag", target: { kind: "tag", id: "t1" }, subject: { kind: "peer", id: "p1" }, network_id: "n-lan", reach: [{ network_id: "n-lan", reach: "ip_only" }] });
const toGroup = grantView({ id: "g-team", target: { kind: "app", id: "a2" }, subject: { kind: "group", id: "g1" } });

describe("AccessList, who can reach this", () => {
  const access: EffectiveAccess[] = [
    { grant_id: "g-direct", scope: { kind: "port", port: 80, proto: "tcp" }, ports: [{ start: 80, end: 80, proto: "tcp" }], network_id: null, subject: { kind: "peer", id: "p1" }, origin: { kind: "direct" } },
    { grant_id: "g-tag", scope: { kind: "all" }, ports: [{ start: 80, end: 80, proto: "tcp" }], network_id: "n-lan", subject: { kind: "peer", id: "p1" }, origin: { kind: "tag", tag_id: "t1" } },
  ];
  const entries = appEntries("a1", access, [direct, viaTag], ctx);

  it("shows port, network, reach and origin; Revoke only on the direct entry", async () => {
    const onRevoke = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<AccessList entries={entries} direction="who" networks={networks} onRevoke={onRevoke} />);
    expect(screen.getByText("80/tcp")).toBeInTheDocument();
    expect(screen.getByText(/on LAN/)).toBeInTheDocument();
    expect(screen.getByText(/Yggdrasil: verified by key/)).toBeInTheDocument();
    expect(screen.getByText(/LAN: IP only/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Revoke/ })).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Revoke alice 80/tcp" }));
    expect(onRevoke).toHaveBeenCalledWith(expect.objectContaining({ grants: [expect.objectContaining({ id: "g-direct" })] }));
  });

  it("an entry that comes through a tag links to the tag; the name links to the peer", async () => {
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<AccessList entries={entries} direction="who" networks={networks} onRevoke={() => {}} />, go);
    await user.click(screen.getByRole("button", { name: "Go to tag web" }));
    expect(go).toHaveBeenCalledWith("apps", { tagId: "t1" });
    await user.click(screen.getAllByRole("button", { name: "alice" })[0]);
    expect(go).toHaveBeenCalledWith("peers", { peerId: "p1" });
  });

  it("is read-only without onRevoke, and says so when nobody can reach it", () => {
    const { unmount } = renderWithProviders(<AccessList entries={entries} direction="who" networks={networks} />);
    expect(screen.queryByRole("button", { name: /^Revoke/ })).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<AccessList entries={[]} direction="who" networks={networks} />);
    expect(screen.getByText("Nobody can reach it.")).toBeInTheDocument();
  });
});

describe("AccessList, what this can reach", () => {
  const entries = subjectEntries({ kind: "peer", id: "p1" }, null, [direct, toGroup], ctx);

  it("names the targets, with the group the access comes through", async () => {
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<AccessList entries={entries} direction="what" networks={networks} onRevoke={() => {}} />, go);
    expect(screen.getByRole("button", { name: "nginx" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "redis" })).toBeInTheDocument();
    // Only the peer's own grant is revocable here; the group's is changed at the group.
    expect(screen.getAllByRole("button", { name: /^Revoke/ })).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Go to group team" }));
    expect(go).toHaveBeenCalledWith("peers", { groupId: "g1" });
    await user.click(screen.getByRole("button", { name: "redis" }));
    expect(go).toHaveBeenCalledWith("apps", { appId: "a2" });
  });

  it("with several things selected, says how many have each access", () => {
    renderWithProviders(
      <AccessList
        entries={[{ ...entries[0], have: 2, of: 3 }, { ...entries[1], have: 3, of: 3 }]}
        direction="what"
        networks={networks}
        unit="peers"
      />,
    );
    expect(screen.getByText("2 of 3 peers")).toBeInTheDocument();
    expect(screen.getByText("all 3 peers")).toBeInTheDocument();
  });

  it("marks the entry of the subject a cell of the overview was clicked for", () => {
    renderWithProviders(
      <AccessList entries={appEntries("a1", [{ grant_id: "g-direct", scope: { kind: "all" }, ports: [{ start: 80, end: 80, proto: "tcp" }], network_id: null, subject: { kind: "peer", id: "p1" }, origin: { kind: "direct" } }], [direct], ctx)} direction="who" networks={networks} highlight={{ subject: { kind: "peer", id: "p1" }, networkId: null }} />,
    );
    expect(document.querySelector(".access-highlight")).not.toBeNull();
  });
});

describe("AccessList, reservation origin", () => {
  it("an access that comes through a reservation links to it on the Reserved tab", async () => {
    const go = vi.fn();
    const user = userEvent.setup();
    const g = grantView({ id: "g-res", target: { kind: "reservation", id: "r1" }, subject: { kind: "peer", id: "p1" } });
    const access: EffectiveAccess[] = [
      { grant_id: "g-res", scope: { kind: "all" }, ports: [], network_id: null, subject: { kind: "peer", id: "p1" }, origin: { kind: "reservation", reservation_id: "r1" } },
    ];
    const entries = appEntries("a1", access, [g], { ...ctx, reservations: [{ id: "r1", label: "front" }] });
    renderWithProviders(<AccessList entries={entries} direction="who" networks={networks} onRevoke={() => {}} />, go);
    expect(screen.queryByRole("button", { name: /^Revoke/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Go to reservation front" }));
    expect(go).toHaveBeenCalledWith("reserved", { reservationId: "r1" });
  });

  it("what a peer can reach lists a reservation grant as `reserved <name>`, linking to it", async () => {
    const go = vi.fn();
    const user = userEvent.setup();
    const g = grantView({ id: "g-res", target: { kind: "reservation", id: "r1" }, subject: { kind: "peer", id: "p1" } });
    const entries = subjectEntries({ kind: "peer", id: "p1" }, null, [g], { ...ctx, reservations: [{ id: "r1", label: "front" }] });
    renderWithProviders(<AccessList entries={entries} direction="what" networks={networks} />, go);
    await user.click(screen.getByRole("button", { name: "reserved front" }));
    expect(go).toHaveBeenCalledWith("reserved", { reservationId: "r1" });
  });
});

