import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AccessPage from "./AccessPage";
import type { App, ChangesRequest, GrantView, Peer, Tag } from "../api";
import { alice, app1, grantView, mockDaemon, renderWithProviders, saved } from "../test/helpers";

const port = (n: number) => ({ port: n, proto: "tcp" as const, listening: true, last_seen: app1.first_seen, family: "dual" as const });
const nginx: App = { ...app1, reviewed: true, ports: [port(80), port(443)] };
const redis: App = { ...app1, id: "a2", name: "redis", process_name: "redis", reviewed: true, ports: [port(6379)], addresses: [] };
const bob: Peer = { ...alice, id: "p2", label: "bob", groups: ["g1"], credentials: [] };
const team = { id: "g1", label: "team", members: ["p2"], created_at: "" };
const web: Tag = { id: "t1", label: "web", patterns: [], members: [{ app_id: "a1", port: null }], excluded: [], created_at: "" };

const nginxTo = (over: Partial<GrantView>) => grantView({ id: "g-" + Math.random(), ...over });

const batch = (a: Record<string, unknown>) => {
  const req = a.req as ChangesRequest;
  return saved({ dry_run: req.dry_run, refs: {}, changes: [{ kind: "create", item: "grant", name: "nginx to alice", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" }] }] });
};
const base = {
  list_apps: () => [nginx, redis],
  list_peers: () => [alice, bob],
  list_groups: () => [team],
  list_tags: () => [web],
  changes: batch,
};
const applied = (d: ReturnType<typeof mockDaemon>) =>
  d.calls.filter((c) => c.cmd === "changes" && !(c.args.req as ChangesRequest).dry_run).map((c) => (c.args.req as ChangesRequest).ops);
const cell = (row: string, col: string) => screen.getByRole("button", { name: new RegExp(`^${row} – ${col}:`) });

describe("Access matrix", () => {
  it("stages a click and applies it after a dry-run preview", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: /^nginx – alice: no access/ }));
    expect(screen.getByText("1 staged")).toBeInTheDocument();
    expect(d.count("changes")).toBe(0);
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    const dialog = await screen.findByRole("dialog", { name: "Apply 1 changes?" });
    expect(await within(dialog).findByText("nginx to alice")).toBeInTheDocument();
    expect(d.calls.filter((c) => c.cmd === "changes").every((c) => (c.args.req as ChangesRequest).dry_run)).toBe(true);
    await user.click(within(dialog).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "add_grant", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p1" }, confirm_open: false },
    ]);
  });

  it("toggling a granted cell stages its removal", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [grantView({ id: "g7" })] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: /^nginx – alice: granted/ }));
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([{ op: "remove_grant", grant_id: "g7" }]);
  });

  it("scopes cells to the selected network, and hides the segment columns", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await screen.findByRole("button", { name: /^nginx – alice:/ });
    expect(cell("nginx", "Everyone on LAN")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Network"), "LAN");
    expect(screen.queryByRole("button", { name: /Everyone on LAN/ })).not.toBeInTheDocument();
    await user.click(cell("nginx", "alice"));
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "add_grant", network_id: "n-lan" }]);
  });

  it("shows a grant on some networks as partial", async () => {
    mockDaemon({ ...base, list_grants: () => [grantView({ network_id: "n-lan" })] });
    renderWithProviders(<AccessPage />);
    expect(await screen.findByRole("button", { name: /^nginx – alice: granted on some networks/ })).toBeInTheDocument();
  });

  it("removing from one network keeps an all-networks grant on the others", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [grantView({ id: "g7" })] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await screen.findByRole("option", { name: "LAN" });
    await user.selectOptions(screen.getByLabelText("Network"), "LAN");
    await user.click(await screen.findByRole("button", { name: /^nginx – alice: granted/ }));
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "remove_grant", grant_id: "g7" },
      { op: "add_grant", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p1" }, network_id: "n-ygg", confirm_open: false },
    ]);
  });

  it("offers to add a direct grant or go to the tag on an inherited cell", async () => {
    const tagGrant = grantView({ id: "gt", target: { kind: "tag", id: "t1" }, subject: { kind: "group", id: "g1" } });
    const d = mockDaemon({ ...base, list_grants: () => [tagGrant] });
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />, go);
    // bob is in team, team has access to tag web, nginx is in web.
    const inherited = await screen.findByRole("button", { name: /^nginx – bob: inherited/ });
    await user.click(inherited);
    const pop = await screen.findByRole("dialog", { name: "Inherited access" });
    expect(pop).toHaveTextContent("through group team on tag web");
    expect(d.count("changes")).toBe(0);
    await user.click(within(pop).getByRole("button", { name: "Add a direct grant" }));
    expect(screen.getByText("1 staged")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Apply 1 changes?" })).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "add_grant", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p2" } }]);

    // The other action goes to the tag.
    await user.click(await screen.findByRole("button", { name: /^nginx – group team: inherited/ }));
    await user.click(within(await screen.findByRole("dialog", { name: "Inherited access" })).getByRole("button", { name: "Go to the tag grant" }));
    expect(go).toHaveBeenCalledWith("apps", { tagId: "t1" });
  });

  it("selects a range with shift-click and stages every cell in it", async () => {
    mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: /^nginx – alice:/ }));
    await user.keyboard("{Shift>}");
    await user.click(cell("redis", "bob"));
    await user.keyboard("{/Shift}");
    // nginx and redis rows (and the tag row between them is above): alice and bob columns, plus the group column between.
    expect(screen.getByText(/\d+ staged/)).toBeInTheDocument();
    const staged = Number(/(\d+) staged/.exec(screen.getByText(/\d+ staged/).textContent!)![1]);
    // rows nginx..redis (2) x columns alice..bob (alice, bob adjacent = 2)
    expect(staged).toBe(4);
  });

  it("selects a whole row from its header", async () => {
    mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: "redis" }));
    // team, alice, bob, Anyone, Everyone on LAN
    expect(screen.getByText("5 staged")).toBeInTheDocument();
  });

  it("asks before opening to Anyone", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: /^redis – Anyone:/ }));
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Apply 1 changes?" })).getByRole("button", { name: "Apply" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    expect(applied(d)).toHaveLength(0);
    await user.click(within(confirm).getByRole("button", { name: "Open to anyone" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "add_grant", subject: { kind: "anyone" }, confirm_open: true }]);
  });

  it("a segment column grants Anyone on that network", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: /^redis – Everyone on LAN:/ }));
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Apply 1 changes?" })).getByRole("button", { name: "Apply" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Open to anyone?" })).getByRole("button", { name: "Open to anyone" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "add_grant", subject: { kind: "anyone" }, network_id: "n-lan", confirm_open: true }]);
  });

  it("expands an app into its ports", async () => {
    const d = mockDaemon({ ...base, list_grants: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<AccessPage />);
    await user.click(await screen.findByRole("button", { name: "Expand ports of nginx" }));
    await user.click(await screen.findByRole("button", { name: /^443\/tcp – alice:/ }));
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ port: { port: 443, proto: "tcp" } }]);
    void nginxTo;
  });
});
