// Rows inside an app (All ports, ports, attached port groups) and the port groups themselves.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import type { AppDetail, ChangeOp, ChangesRequest, EffectiveAccess, GrantView, SocketGroup, Tag } from "../api";
import {
  batch, detail, grantView, mkApp, mkPeer, mkTag, memoryStorage, mockDaemon, renderWithProviders,
} from "../test/helpers";

const nginx = mkApp("a1", "nginx", [80, 443]);
const redis = mkApp("a2", "redis-server", [6379]);
const odd = mkApp("a3", "mystery", [9999], { identity_note: "unidentified" });
const apps = [nginx, redis, odd];

const alice = mkPeer("p1", "alice");
const bob = mkPeer("p2", "bob");
const carol = mkPeer("p3", "carol");

const T0 = "2026-01-01T00:00:00Z";
const passive: SocketGroup = { id: "sg1", label: "passive", ports: [{ start: 50000, end: 51000, proto: "tcp" }], apps: ["a1"], created_at: T0 };
const dns: SocketGroup = { id: "sg2", label: "dns", ports: [{ start: 53, end: 53, proto: "udp" }, { start: 5353, end: 5353, proto: "udp" }], apps: [], created_at: T0 };

const ftp: Tag = { ...mkTag("t-ftp", "ftp"), members: [{ app_id: "a1", scope: { kind: "group", id: "sg1" } }] };
const mon: Tag = { ...mkTag("t-mon", "monitoring"), members: [{ app_id: "a1", scope: { kind: "port", port: 443, proto: "tcp" } }] };
const web = mkTag("t-web", "web", ["a2"]);

const gAll = grantView({ id: "g-all", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p1" } });
const gGroup = grantView({ id: "g-grp", target: { kind: "app", id: "a1" }, scope: { kind: "group", id: "sg1" }, subject: { kind: "peer", id: "p2" } });
const gFtp = grantView({ id: "g-ftp", target: { kind: "tag", id: "t-ftp" }, subject: { kind: "peer", id: "p3" } });
const grants = [gAll, gGroup, gFtp];

const access = (g: GrantView, origin: EffectiveAccess["origin"] = { kind: "direct" }): EffectiveAccess => ({
  grant_id: g.id, scope: g.scope, ports: [], network_id: g.network_id, subject: g.subject, origin,
});

const requests = (d: ReturnType<typeof mockDaemon>) => d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest);
const applied = (d: ReturnType<typeof mockDaemon>) => requests(d).filter((r) => !r.dry_run).map((r) => r.ops);

function setup(over: Parameters<typeof mockDaemon>[0] = {}, groups: SocketGroup[] = [passive, dns]) {
  const details: Record<string, AppDetail> = {
    a1: detail(nginx, {
      grants: [gAll, gGroup],
      access: [access(gAll), access(gGroup), access(gFtp, { kind: "tag", tag_id: "t-ftp" })],
      tags: ["t-ftp", "t-mon"],
      socket_groups: groups.filter((g) => g.apps.includes("a1")),
    }),
    a2: detail(redis),
    a3: detail(odd),
  };
  return mockDaemon({
    list_apps: () => apps,
    get_app: (a) => details[a.id as string],
    list_peers: () => [alice, bob, carol],
    list_tags: () => [ftp, mon, web],
    list_grants: () => grants,
    list_socket_groups: () => groups,
    changes: (a) => batch(a.req as ChangesRequest),
    ...over,
  });
}

const inList = () => within(screen.getByRole("table", { name: "Apps and tags" }));
const inspector = () => screen.getByRole("region", { name: "Details" });
const rowOf = (ports: HTMLElement, label: string) => within(ports).getByText(label, { selector: ".port-name" }).closest("li")!;
async function openApp(user: ReturnType<typeof userEvent.setup>, name: RegExp | string) {
  await user.click(await inList().findByRole("button", { name }));
  const ports = (await within(inspector()).findByRole("heading", { name: "Ports" })).closest("section")!;
  return ports as HTMLElement;
}

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("The Ports section of an app", () => {
  it("has the same parts on every row, and each access only on the row that names it", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user, /^nginx/);
    const labels = [...ports.querySelectorAll(".port-name")].map((e) => e.textContent);
    expect(labels).toEqual(["All ports", "80/tcp", "443/tcp", "passive"]);
    for (const label of labels) {
      const row = rowOf(ports, label!);
      expect(within(row).getByRole("button", { name: `Add or remove tags of ${label}` })).toHaveTextContent("+");
      expect(within(row).getByRole("button", { name: `Add access to ${label}` })).toBeInTheDocument();
    }
    // Direct on All ports; direct on the group and through the tag on the group; nothing on the ports.
    expect(rowOf(ports, "All ports")).toHaveTextContent("alice");
    expect(rowOf(ports, "All ports")).not.toHaveTextContent("bob");
    expect(rowOf(ports, "passive")).toHaveTextContent("bob");
    expect(rowOf(ports, "passive")).toHaveTextContent("carol");
    expect(within(rowOf(ports, "passive")).getByRole("button", { name: "Go to tag ftp" })).toBeInTheDocument();
    expect(rowOf(ports, "443/tcp")).not.toHaveTextContent("alice");
    expect(rowOf(ports, "passive")).toHaveTextContent("50000-51000/tcp");
    // Tags sit on their row.
    expect(within(rowOf(ports, "passive")).getByRole("button", { name: "ftp" })).toBeInTheDocument();
    expect(within(rowOf(ports, "443/tcp")).getByRole("button", { name: "monitoring" })).toBeInTheDocument();
    expect(within(rowOf(ports, "All ports")).queryByRole("button", { name: "ftp" })).not.toBeInTheDocument();
  });

  it("says once that All ports also reaches a row, as a link to the All ports row", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user, /^nginx/);
    expect(within(rowOf(ports, "All ports")).queryByText(/also reachable/)).not.toBeInTheDocument();
    for (const label of ["80/tcp", "443/tcp", "passive"]) {
      const line = within(rowOf(ports, label)).getByRole("button", { name: "also reachable by everyone on All ports" });
      expect(line).toHaveClass("link-btn");
    }
    // The line is the only mention: alice is not repeated.
    expect(within(rowOf(ports, "passive")).queryByRole("button", { name: "alice" })).not.toBeInTheDocument();
  });

  it("Add access on a group row has that group chosen; the grant is sent with the group scope", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user, /^nginx/);
    await user.click(within(rowOf(ports, "passive")).getByRole("button", { name: "Add access to passive" }));
    const form = screen.getByRole("form", { name: "Add access" });
    const chips = within(within(form).getByRole("group", { name: "What to open" }));
    expect([...within(form).getByRole("group", { name: "What to open" }).querySelectorAll("button")].map((b) => b.textContent)).toEqual(["All ports", "80/tcp", "443/tcp", "passive"]);
    expect(chips.getByRole("button", { name: "passive" })).toHaveAttribute("aria-pressed", "true");
    expect(chips.getByRole("button", { name: "All ports" })).toHaveAttribute("aria-pressed", "false");
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "group", id: "sg1" }, subject: { kind: "peer", id: "p1" }, confirm_open: false },
    ]]));
  });

  it("the chips are only the groups attached to the app, and every group for a tag", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user, "redis-server");
    await user.click(within(rowOf(ports, "All ports")).getByRole("button", { name: "Add access to All ports" }));
    let chips = within(screen.getByRole("form", { name: "Add access" })).getByRole("group", { name: "What to open" });
    expect([...chips.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["All ports", "6379/tcp"]);
    await user.click(inList().getByRole("checkbox", { name: "Select web" }));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access…" }));
    chips = within(screen.getByRole("form", { name: "Add access" })).getByRole("group", { name: "What to open" });
    expect([...chips.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["All ports", "6379/tcp", "passive", "dns"]);
  });

  it("a group chip is granted only on the apps that have it attached", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select nginx" }));
    await user.click(inList().getByRole("checkbox", { name: "Select redis-server" }));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "bob" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "passive" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "group", id: "sg1" }, subject: { kind: "peer", id: "p2" }, confirm_open: false },
    ]);
  });
});

describe("Attach port group", () => {
  const groupRow = async (user: ReturnType<typeof userEvent.setup>, label: RegExp) => {
    await user.click(within(inspector()).getByRole("button", { name: "Attach port group" }));
    return screen.getByRole("checkbox", { name: label });
  };

  it("attaching shows the review when the dry run reports a change of reach, then applies", async () => {
    const gaining = { kind: "update" as const, item: "socket_group" as const, name: "attach dns on redis-server", detail: "reachable by alice", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" as const }] };
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [gaining]) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await openApp(user, "redis-server");
    await user.click(await groupRow(user, /^dns/));
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent("attach dns on redis-server");
    expect(review).toHaveTextContent("update port group");
    expect(applied(d)).toEqual([]);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "attach_socket_group", group_id: "sg2", app_id: "a2", confirm_open: false }]]));
  });

  it("applies at once when nobody gains access, and an attached group can be detached with Undo", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await openApp(user, "redis-server");
    await user.click(await groupRow(user, /^dns/));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "attach_socket_group", group_id: "sg2", app_id: "a2", confirm_open: false }]]));
    expect(screen.queryByRole("region", { name: "Review before applying" })).not.toBeInTheDocument();
  });

  it("Detach on a group row goes through the same rule and offers Undo", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user, /^nginx/);
    await user.click(within(rowOf(ports, "passive")).getByRole("button", { name: "Detach passive" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "detach_socket_group", group_id: "sg1", app_id: "a1" }]]));
    await user.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(applied(d)).toHaveLength(2));
    expect(applied(d)[1]).toEqual([{ op: "attach_socket_group", group_id: "sg1", app_id: "a1", confirm_open: true }]);
  });

  it("asks the ports of a new group and creates and attaches it in one batch with a ref", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await openApp(user, /^nginx/);
    await user.click(within(inspector()).getByRole("button", { name: "Attach port group" }));
    await user.type(screen.getByRole("combobox", { name: "Search Port groups" }), "ftp-data");
    await user.click(screen.getByRole("option", { name: /Create/ }));
    const form = await screen.findByRole("form", { name: "New port group" });
    expect(within(form).getByRole("button", { name: "Create and attach" })).toBeDisabled();
    const input = within(form).getByLabelText("Add a port or range");
    await user.type(input, "banana{Enter}");
    expect(within(form).getByRole("alert")).toHaveTextContent("is not a port");
    await user.clear(input);
    await user.type(input, "2121/tcp{Enter}");
    await user.type(input, "50000-50100/tcp{Enter}");
    await user.click(within(form).getByRole("button", { name: "Create and attach" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual<ChangeOp[]>([
      { op: "create_socket_group", ref: "$group", label: "ftp-data", ports: [{ start: 2121, end: 2121, proto: "tcp" }, { start: 50000, end: 50100, proto: "tcp" }], apps: [], confirm_open: false },
      { op: "attach_socket_group", group_id: "$group", app_id: "a1", confirm_open: false },
    ]);
  });

  it("an unidentified app takes none", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^mystery/ }));
    await within(inspector()).findByRole("heading", { name: "Ports" });
    expect(within(inspector()).queryByRole("button", { name: "Attach port group" })).not.toBeInTheDocument();
  });
});

describe("Port groups in the list", () => {
  it("has a section between Tags and Apps with ports, apps and grants; the app rows summarise their tags and groups", async () => {
    setup();
    renderWithProviders(<AppsPage />);
    await inList().findByRole("button", { name: /^nginx/ });
    const heads = [...document.querySelectorAll(".section-label")].map((e) => e.textContent);
    expect(heads).toEqual(["Tags (3)", "Port groups (2)", "Apps (3)"]);
    const row = inList().getByRole("checkbox", { name: "Select passive" }).closest("tr")!;
    expect(row).toHaveTextContent("50000-51000/tcp");
    expect(row).toHaveTextContent("1 app");
    expect(row).toHaveTextContent("1 grant");
    expect(inList().getByRole("checkbox", { name: "Select dns" }).closest("tr")).toHaveTextContent("53/udp, 5353/udp");
    expect(inList().getByRole("checkbox", { name: "Select dns" }).closest("tr")).toHaveTextContent("no grants");
    // The app row: a tag on a port or a group is written with it, and the groups follow the ports.
    const app = inList().getByRole("button", { name: /^nginx/ }).closest("tr")!;
    expect(within(app).getByRole("button", { name: "ftp passive" })).toHaveClass("tag-pill");
    expect(within(app).getByRole("button", { name: "monitoring 443/tcp" })).toHaveClass("tag-pill");
    expect(app).toHaveTextContent("80/tcp, 443/tcp passive");
    expect(inList().getByRole("columnheader", { name: "Ports" })).toBeInTheDocument();
  });

  it("with subject columns an app expands to its ports and groups", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await screen.findByRole("button", { name: /^Columns/ }));
    await user.click(screen.getByRole("checkbox", { name: "bob" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    await user.click(await inList().findByRole("button", { name: "Expand ports of nginx" }));
    expect(inList().getByRole("button", { name: "nginx – bob: no access" })).toBeInTheDocument();
    expect(inList().getByRole("button", { name: "passive – bob: granted" })).toBeInTheDocument();
    expect(inList().getByRole("button", { name: "passive – alice: inherited" })).toBeInTheDocument();
    expect(inList().getByRole("button", { name: "80/tcp – alice: inherited" })).toBeInTheDocument();
  });

  it("New port group asks for a name and ports and creates it through the batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: "New port group" }));
    expect(await screen.findByRole("heading", { name: "New port group" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Port group name"), "mail");
    await user.type(screen.getByLabelText("Add a port or range"), "25/tcp{Enter}");
    await user.click(screen.getByRole("button", { name: "Create port group" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "create_socket_group", label: "mail", ports: [{ start: 25, end: 25, proto: "tcp" }], apps: [], confirm_open: false },
    ]]));
  });
});

describe("Port group inspector", () => {
  async function openGroup(user: ReturnType<typeof userEvent.setup>, label: string) {
    await user.click(await inList().findByRole("checkbox", { name: `Select ${label}` }));
    return within(await screen.findByRole("complementary", { name: "Port group details" }));
  }

  it("shows ports, attached apps and who can reach it per app", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const panel = await openGroup(user, "passive");
    expect(panel.getByRole("heading", { name: "passive" })).toBeInTheDocument();
    expect(panel.getByLabelText("Name")).toHaveValue("passive");
    expect(panel.getByText("50000-51000/tcp")).toBeInTheDocument();
    const who = panel.getByRole("heading", { name: "Who can reach it" }).closest("section")!;
    expect(within(who).getByRole("heading", { name: "nginx" })).toBeInTheDocument();
    expect(within(who).getByRole("button", { name: "bob" })).toBeInTheDocument();
    expect(within(who).queryByRole("button", { name: "alice" })).not.toBeInTheDocument();
    expect(within(who).getByRole("button", { name: "Add access to passive" })).toBeInTheDocument();
  });

  it("adding a range shows the review when it lets more in; removing applies at once with Undo", async () => {
    const gaining = { kind: "update" as const, item: "socket_group" as const, name: "add 60000-60010/tcp to passive on nginx", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" as const }] };
    const d = setup({ changes: (a) => ((a.req as ChangesRequest).ops[0].op === "update_socket_group" && ((a.req as ChangesRequest).ops[0] as { ports: unknown[] }).ports.length > 1 ? batch(a.req as ChangesRequest, true, [gaining]) : batch(a.req as ChangesRequest)) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const panel = await openGroup(user, "passive");
    const input = panel.getByLabelText("Add a port or range");
    await user.type(input, "70000/tcp{Enter}");
    expect(panel.getByRole("alert")).toHaveTextContent("1 to 65535");
    await user.clear(input);
    await user.type(input, "60000-60010/tcp{Enter}");
    const review = await panel.findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent("60000-60010/tcp");
    expect(applied(d)).toEqual([]);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "update_socket_group", group_id: "sg1", ports: [{ start: 50000, end: 51000, proto: "tcp" }, { start: 60000, end: 60010, proto: "tcp" }], confirm_open: false },
    ]]));
  });

  it("removing a range applies at once and Undo puts it back", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const panel = await openGroup(user, "dns");
    await user.click(panel.getByRole("button", { name: "Remove 5353/udp" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "update_socket_group", group_id: "sg2", ports: [{ start: 53, end: 53, proto: "udp" }], confirm_open: false },
    ]]));
    await user.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(applied(d)).toHaveLength(2));
    expect(applied(d)[1]).toEqual([
      { op: "update_socket_group", group_id: "sg2", ports: dns.ports, confirm_open: true },
    ]);
  });

  it("attaches an app from the picker (not an unidentified one) through the rule", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const panel = await openGroup(user, "dns");
    await user.click(panel.getByRole("button", { name: "Attach or detach apps" }));
    expect(screen.queryByRole("checkbox", { name: "mystery" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "redis-server" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "attach_socket_group", group_id: "sg2", app_id: "a2", confirm_open: false }]]));
  });

  it("Delete asks first, and the daemon's refusal naming the users is shown", async () => {
    const d = setup({
      changes: (a) => {
        if ((a.req as ChangesRequest).ops[0].op === "delete_socket_group") throw { code: "conflict", message: "port group passive is used by a grant on nginx, tag ftp" };
        return batch(a.req as ChangesRequest);
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const panel = await openGroup(user, "passive");
    await user.click(panel.getByRole("button", { name: "Delete port group" }));
    expect(requests(d)).toHaveLength(0);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete port group" }));
    expect(await panel.findByRole("alert")).toHaveTextContent("used by a grant on nginx, tag ftp");
    expect(applied(d)).toEqual([]);
  });

  it("several groups show where they are attached, with mixed state, and Delete N", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select passive" }));
    await user.click(inList().getByRole("checkbox", { name: "Select dns" }));
    const panel = within(await screen.findByRole("complementary", { name: "Port groups details" }));
    expect(panel.getByRole("heading", { name: "2 port groups selected" })).toBeInTheDocument();
    expect(panel.getByText("nginx")).toBeInTheDocument();
    expect(panel.getByText("1 of 2")).toBeInTheDocument();
    await user.click(panel.getByRole("button", { name: "Attach or detach apps" }));
    const box = screen.getByRole("checkbox", { name: "nginx" }) as HTMLInputElement;
    expect(box.indeterminate).toBe(true);
    await user.keyboard("{Escape}");
    await user.click(panel.getByRole("button", { name: "Delete 2 port groups" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete port groups" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "delete_socket_group", group_id: "sg1" }, { op: "delete_socket_group", group_id: "sg2" },
    ]]));
  });
});

describe("Tag inspector members", () => {
  it("lists every member as app · row and the picker offers an app's rows", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select ftp" }));
    const panel = within(await screen.findByRole("region", { name: "Details" }));
    const members = panel.getByRole("heading", { name: /Members \(1\)/ }).closest("section")!;
    expect(members).toHaveTextContent("nginx · passive");
    await user.click(panel.getByRole("button", { name: "Add or remove members" }));
    await user.click(screen.getByRole("checkbox", { name: "nginx" }));
    const rows = within(await panel.findByRole("group", { name: "Rows of nginx in ftp" }));
    expect([...panel.getByRole("group", { name: "Rows of nginx in ftp" }).querySelectorAll(".scope-chip")].map((b) => b.textContent)).toEqual(["All ports", "80/tcp", "443/tcp", "passive"]);
    await user.click(rows.getByRole("button", { name: "80/tcp" }));
    // The tag has a grant, so the batch is first checked; no reach in the answer, so it applies.
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "add_tag_member", tag_id: "t-ftp", app_id: "a1", scope: { kind: "port", port: 80, proto: "tcp" }, confirm_open: false }]]));
  });
});

describe("Wording", () => {
  const banned = /whole app|whole tag|\bsockets?\b|socket group|all sockets/i;

  it("no screen says Whole app, socket or socket group", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const text = () => document.body.textContent ?? "";
    await inList().findByRole("button", { name: /^nginx/ });
    expect(text()).not.toMatch(banned);
    expect(text()).toMatch(/Port groups/);

    const ports = await openApp(user, /^nginx/);
    await user.click(within(rowOf(ports, "All ports")).getByRole("button", { name: "Add access to All ports" }));
    await user.click(within(inspector()).getByRole("button", { name: "Attach port group" }));
    expect(text()).not.toMatch(banned);
    await user.keyboard("{Escape}");

    await user.click(inList().getByRole("checkbox", { name: "Select passive" }));
    await screen.findByRole("complementary", { name: "Port group details" });
    expect(text()).not.toMatch(banned);

    await user.click(inList().getByRole("checkbox", { name: "Select ftp" }));
    await screen.findByRole("heading", { name: "ftp" });
    expect(text()).not.toMatch(banned);

    await user.click(inList().getByRole("button", { name: "New port group" }));
    await screen.findByRole("heading", { name: "New port group" });
    expect(text()).not.toMatch(banned);
  });
});

