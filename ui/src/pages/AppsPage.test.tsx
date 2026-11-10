import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import type { App, ChangeOp, ChangesRequest, Tag } from "../api";
import { alice, app1, appDetail, grantView, mockDaemon, networks, renderWithProviders, saved } from "../test/helpers";

const port = (n: number) => ({ port: n, proto: "tcp" as const, listening: true, last_seen: app1.first_seen, family: "dual" as const });
const nginx: App = { ...app1, ports: [port(80), port(443)] };
const redis: App = { ...app1, id: "a2", name: "redis", process_name: "redis", exe_path: "/usr/bin/redis", reviewed: true, ports: [port(6379)], addresses: [] };
const dnsSvc: App = { ...app1, id: "a3", name: "dnscache", process_name: "svchost.exe", system: true, reviewed: true, ports: [port(53)], addresses: [] };
const team = { id: "g1", label: "team", members: ["p1"], created_at: app1.first_seen };

/** The daemon's side of a batch: echoes a dry run, records a real one. */
const batch = (a: Record<string, unknown>) => {
  const req = a.req as ChangesRequest;
  return saved({ dry_run: req.dry_run, refs: {}, changes: [] });
};
const applied = (d: ReturnType<typeof mockDaemon>) =>
  d.calls.filter((c) => c.cmd === "changes" && !(c.args.req as ChangesRequest).dry_run).map((c) => (c.args.req as ChangesRequest).ops);

async function openGrantEditor() {
  const user = userEvent.setup();
  renderWithProviders(<AppsPage />);
  await user.click(await screen.findByRole("button", { name: "nginx" }));
  await user.click(await screen.findByRole("button", { name: "Grant access…" }));
  return { user, dialog: await screen.findByRole("dialog", { name: "Grant access" }) };
}

const base = {
  list_apps: () => [nginx, redis, dnsSvc],
  get_app: () => ({ ...appDetail, ...nginx, grants: [], access: [], tags: [] }),
  list_groups: () => [team],
  changes: batch,
};

describe("Apps page", () => {
  it("lists apps with a pending badge, and shows each port's access with its origin", async () => {
    mockDaemon({
      ...base,
      list_tags: () => [{ id: "t1", label: "web", patterns: [], members: [{ app_id: "a1", port: null }], excluded: [], created_at: "" } satisfies Tag],
      get_app: () => ({
        ...appDetail, ...nginx,
        grants: [grantView({ reach: [{ network_id: "n-ygg", reach: "verified" }, { network_id: "n-lan", reach: "not_reachable" }] })],
        access: [
          { grant_id: "g1", port: null, network_id: null, subject: { kind: "peer", id: "p1" }, origin: { kind: "direct" } },
          { grant_id: "g9", port: { port: 443, proto: "tcp" }, network_id: null, subject: { kind: "group", id: "g1" }, origin: { kind: "tag", tag_id: "t1" } },
        ],
      }),
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const row = (await screen.findByRole("button", { name: "nginx" })).closest("tr")!;
    expect(within(row).getByText("pending")).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: "nginx" }));
    expect(await screen.findAllByText("Yggdrasil: verified by key")).not.toHaveLength(0);
    expect(screen.getAllByText("direct").length).toBeGreaterThan(0);
    expect(screen.getByText("via tag web")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Revoke access for alice" }).length).toBeGreaterThan(0);
  });

  it("shows system services as a collapsed group", async () => {
    mockDaemon(base);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await screen.findByRole("button", { name: "nginx" });
    expect(screen.queryByRole("button", { name: "dnscache" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /System services \(1\)/ }));
    expect(screen.getByRole("button", { name: "dnscache" })).toBeInTheDocument();
  });

  it("grants several ports to several subjects in one batch", async () => {
    const d = mockDaemon({ ...base, list_peers: () => [alice] });
    const { user, dialog } = await openGrantEditor();
    await user.click(within(dialog).getByRole("checkbox", { name: "All ports" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "80/tcp" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "443/tcp" }));
    await user.click(within(dialog).getByRole("button", { name: "alice" }));
    await user.type(within(dialog).getByRole("combobox"), "team");
    await user.click(within(dialog).getByRole("button", { name: "group team" }));
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    const grants = (applied(d)[0] as Extract<ChangeOp, { op: "add_grant" }>[]);
    expect(grants).toHaveLength(4);
    expect(grants.map((g) => [g.port?.port, g.subject.kind])).toEqual([
      [80, "peer"], [80, "group"], [443, "peer"], [443, "group"],
    ]);
    expect(grants.every((g) => g.target.kind === "app" && g.confirm_open === false)).toBe(true);
    // The preview was a dry run of the same operations.
    const dry = d.calls.filter((c) => c.cmd === "changes" && (c.args.req as ChangesRequest).dry_run).pop();
    expect((dry!.args.req as ChangesRequest).ops).toEqual(applied(d)[0]);
  });

  it("creates a new peer from a pasted credential in the same batch, by reference", async () => {
    const d = mockDaemon({ ...base, list_peers: () => [alice] });
    const { user, dialog } = await openGrantEditor();
    await user.type(within(dialog).getByRole("combobox"), "10.0.0.5");
    await user.click(await within(dialog).findByRole("button", { name: /New peer from/ }));
    // A new peer needs a label before anything can be sent.
    expect(within(dialog).getByRole("button", { name: "Grant" })).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Label for new peer 10.0.0.5"), "laptop");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "create_peer", ref: "$new0", label: "laptop", credentials: [{ kind: "ip", value: "10.0.0.5", label: null }] },
      { op: "add_grant", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "$new0" }, confirm_open: false },
    ]);
  });

  it("shows a daemon error on the new peer's chip", async () => {
    mockDaemon({
      ...base,
      changes: (a) => {
        if ((a.req as ChangesRequest).dry_run) return batch(a);
        throw { code: "conflict", message: "operation 0: peer label already in use", details: null };
      },
    });
    const { user, dialog } = await openGrantEditor();
    await user.type(within(dialog).getByRole("combobox"), "10.0.0.5");
    await user.click(await within(dialog).findByRole("button", { name: /New peer from/ }));
    await user.type(within(dialog).getByLabelText("Label for new peer 10.0.0.5"), "alice");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    expect(await within(dialog).findByText(/peer label already in use/)).toBeInTheDocument();
  });

  it("asks before opening to Anyone and sends confirm_open", async () => {
    const d = mockDaemon(base);
    const { user, dialog } = await openGrantEditor();
    await user.click(within(dialog).getByRole("button", { name: "Anyone" }));
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    expect(applied(d)).toHaveLength(0);
    await user.click(within(confirm).getByRole("button", { name: "Open to anyone" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "add_grant", subject: { kind: "anyone" }, confirm_open: true }]);
  });

  it("words the Anyone confirmation for a network as everyone on it, and sends the network", async () => {
    const d = mockDaemon(base);
    const { user, dialog } = await openGrantEditor();
    await user.click(within(dialog).getByRole("button", { name: "Anyone" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "LAN" }));
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to everyone on LAN?" });
    await user.click(within(confirm).getByRole("button", { name: "Open to everyone on LAN" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ network_id: "n-lan", confirm_open: true }]);
  });

  it("cancelling the Anyone confirmation grants nothing", async () => {
    const d = mockDaemon(base);
    const { user, dialog } = await openGrantEditor();
    await user.click(within(dialog).getByRole("button", { name: "Anyone" }));
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    await user.click(within(confirm).getByRole("button", { name: "Cancel" }));
    expect(applied(d)).toHaveLength(0);
  });

  it("handles a confirmation_required answer by confirming and retrying", async () => {
    let n = 0;
    const d = mockDaemon({
      ...base,
      list_peers: () => [alice],
      changes: (a) => {
        const req = a.req as ChangesRequest;
        if (req.dry_run) return batch(a);
        n++;
        if (!req.ops.every((o) => o.op !== "add_grant" || o.confirm_open)) {
          throw { code: "confirmation_required", message: "confirm opening to anyone", details: null };
        }
        return batch(a);
      },
    });
    const { user, dialog } = await openGrantEditor();
    await user.click(within(dialog).getByRole("button", { name: "alice" }));
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    await user.click(within(confirm).getByRole("button", { name: "Open to anyone" }));
    await waitFor(() => expect(n).toBe(2));
    expect(applied(d)[1]).toMatchObject([{ confirm_open: true }]);
  });

  it("selects a range with shift and grants to all the selected apps", async () => {
    const d = mockDaemon({ ...base, list_peers: () => [alice] });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await screen.findByRole("button", { name: "nginx" });
    await user.click(screen.getByRole("checkbox", { name: "Select nginx" }));
    await user.keyboard("{Shift>}");
    await user.click(screen.getByRole("checkbox", { name: "Select redis" }));
    await user.keyboard("{/Shift}");
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Grant…" }));
    const dialog = await screen.findByRole("dialog", { name: "Grant access" });
    await user.click(within(dialog).getByRole("button", { name: "alice" }));
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect((applied(d)[0] as { target: { id: string } }[]).map((o) => o.target.id).sort()).toEqual(["a1", "a2"]);
  });

  it("tags the selected apps with a new tag in one batch", async () => {
    const d = mockDaemon(base);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await screen.findByRole("checkbox", { name: "Select nginx" }));
    await user.click(screen.getByRole("button", { name: "Tag…" }));
    const dialog = await screen.findByRole("dialog", { name: /Tag 1 item/ });
    await user.selectOptions(within(dialog).getByLabelText("Tag"), "New tag…");
    await user.type(within(dialog).getByLabelText("New tag name"), "web");
    await user.click(within(dialog).getByRole("button", { name: "Tag" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "create_tag", ref: "$tag", label: "web", patterns: [] },
      { op: "add_tag_member", tag_id: "$tag", app_id: "a1" },
    ]);
  });

  it("shows this machine only for a Local-only app, without a grant button", async () => {
    mockDaemon({
      ...base,
      get_app: () => ({ ...appDetail, ...nginx, addresses: [{ ...appDetail.addresses[0], network_id: "n-local" }] }),
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await screen.findByRole("button", { name: "nginx" }));
    expect((await screen.findAllByText(/This machine only/)).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Grant access…" })).not.toBeInTheDocument();
  });

  it("states the IPv4 exposure of an app that listens on IPv4", async () => {
    mockDaemon(base);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await screen.findByRole("button", { name: "nginx" }));
    expect(await screen.findByTestId("ipv4-status")).toHaveTextContent("open to everyone");
    expect(networks.length).toBeGreaterThan(0);
  });
});
