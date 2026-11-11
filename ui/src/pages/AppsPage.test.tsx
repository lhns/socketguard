import type { Focus, Page } from "../nav";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import type { AppDetail, ChangesRequest, EffectiveAccess, GrantView, Scope, Tag } from "../api";
import {
  batch, detail, grantView, mkApp, mkGroup, mkPeer, mkReservation, mkTag, memoryStorage, mockDaemon, renderWithProviders, saved,
} from "../test/helpers";

const nginx = mkApp("a1", "nginx", [80, 443], { reviewed: false });
const redis = mkApp("a2", "redis-server", [6379]);
const sshd = mkApp("a3", "sshd", [22]);
const svc = mkApp("s1", "svchost (RpcSs)", [135], { system: true });
const apps = [nginx, redis, sshd, svc];

const alice = mkPeer("p1", "alice", { groups: ["g1"] });
const bob = mkPeer("p2", "bob");
const team = mkGroup("g1", "team", ["p1"]);
const web = mkTag("t1", "web", ["a1", "a2"], ["nginx*"]);
const data = mkTag("t2", "data", ["a2"]);

const gAlice = grantView({ id: "g-alice", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p1" } });
const gLan = grantView({ id: "g-lan", target: { kind: "app", id: "a2" }, subject: { kind: "peer", id: "p1" }, network_id: "n-lan", reach: [{ network_id: "n-lan", reach: "ip_only" }] });
const gTag = grantView({ id: "g-tag", target: { kind: "tag", id: "t1" }, subject: { kind: "peer", id: "p2" } });

const access = (g: GrantView, origin: EffectiveAccess["origin"] = { kind: "direct" }): EffectiveAccess => ({
  grant_id: g.id, scope: g.scope, ports: g.scope.kind === "port" ? [{ start: g.scope.port, end: g.scope.port, proto: g.scope.proto }] : [{ start: 8080, end: 8080, proto: "tcp" }], network_id: g.network_id, subject: g.subject, origin,
});

const requests = (d: ReturnType<typeof mockDaemon>) => d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest);
const applied = (d: ReturnType<typeof mockDaemon>) => requests(d).filter((r) => !r.dry_run).map((r) => r.ops);

/** The Apps page on a small fleet; `over` replaces handlers. */
function setup(over: Parameters<typeof mockDaemon>[0] = {}, tags: Tag[] = [web, data], grants: GrantView[] = [gAlice, gLan, gTag]) {
  const details: Record<string, AppDetail> = {
    a1: detail(nginx, { grants: [gAlice], access: [access(gAlice), access(gTag, { kind: "tag", tag_id: "t1" })], tags: ["t1"] }),
    a2: detail(redis),
    a3: detail(sshd),
    s1: detail(svc),
  };
  const d = mockDaemon({
    list_apps: () => apps,
    get_app: (a) => details[a.id as string],
    list_peers: () => [alice, bob],
    list_groups: () => [team],
    list_tags: () => tags,
    list_grants: () => grants,
    changes: (a) => batch(a.req as ChangesRequest),
    ...over,
  });
  return d;
}

const listTable = () => screen.getByRole("table", { name: "Apps and tags" });
const inList = () => within(listTable());
const inspector = () => screen.getByRole("region", { name: "Details" });
/** The name button of a tag's row (an app's tag pill has the same name). */
const tagRow = (label: string) =>
  within(inList().getByRole("checkbox", { name: `Select ${label}` }).closest("tr")!).getByRole("button", { name: label });
const findTagRow = async (label: string) => {
  await inList().findByRole("checkbox", { name: `Select ${label}` });
  return tagRow(label);
};

let storage = memoryStorage();
beforeEach(() => {
  storage = memoryStorage();
  vi.stubGlobal("localStorage", storage);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Apps list", () => {
  it("has Tags, Apps and System services (collapsed) as sections of one table", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    expect(await inList().findByRole("button", { name: /^nginx/ })).toBeInTheDocument();
    expect(inList().getByText(/^Tags \(2\)/)).toBeInTheDocument();
    expect(inList().getByText(/^Apps \(3\)/)).toBeInTheDocument();
    expect(inList().getByRole("button", { name: /System services \(1\)/ })).toHaveAttribute("aria-expanded", "false");
    expect(inList().queryByRole("button", { name: "svchost (RpcSs)" })).not.toBeInTheDocument();
    // Tags are rows of the table.
    expect(tagRow("web")).toBeInTheDocument();
    await user.click(inList().getByRole("button", { name: /System services/ }));
    expect(inList().getByRole("button", { name: "svchost (RpcSs)" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Access" })).not.toBeInTheDocument();
  });

  it("a search or a filter that matches a system service shows it; pending only filters", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await inList().findByRole("button", { name: /^nginx/ });
    await user.type(screen.getByRole("searchbox", { name: "Filter apps" }), "rpcss");
    expect(inList().getByRole("button", { name: "svchost (RpcSs)" })).toBeInTheDocument();
    expect(inList().queryByRole("button", { name: /^nginx/ })).not.toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox", { name: "Filter apps" }));
    await user.click(screen.getByRole("checkbox", { name: /Pending only/ }));
    expect(inList().getByRole("button", { name: /^nginx/ })).toBeInTheDocument();
    expect(inList().queryByRole("button", { name: "redis-server" })).not.toBeInTheDocument();
  });

  it("a tag pill on an app filters the list by that tag, and the filter can be dropped", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await inList().findByRole("button", { name: /^nginx/ });
    const row = inList().getByRole("button", { name: "sshd" }).closest("tr")!;
    expect(within(row).queryByRole("button")).toBeInTheDocument(); // only the name; sshd has no tag
    await user.click(inList().getAllByRole("button", { name: "web" }).find((b) => b.classList.contains("tag-pill"))!);
    expect(inList().queryByRole("button", { name: "sshd" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Stop filtering by tag web/ }));
    expect(await inList().findByRole("button", { name: "sshd" })).toBeInTheDocument();
  });

  it("keeps ticked apps that a filter hides, and picking a tag starts a new selection", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select nginx" }));
    await user.type(screen.getByRole("searchbox", { name: "Filter apps" }), "redis");
    await user.click(inList().getByRole("checkbox", { name: "Select redis-server" }));
    await user.clear(screen.getByRole("searchbox", { name: "Filter apps" }));
    expect(await screen.findByRole("heading", { name: "2 apps selected" })).toBeInTheDocument();
    expect(inList().getByRole("checkbox", { name: "Select nginx" })).toBeChecked();
    await user.click(inList().getByRole("checkbox", { name: "Select web" }));
    expect(await screen.findByRole("heading", { name: "web" })).toBeInTheDocument();
    expect(inList().getByRole("checkbox", { name: "Select nginx" })).not.toBeChecked();
  });

  it("shift extends a range of checkboxes; select all takes every shown app", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await inList().findByRole("button", { name: /^nginx/ });
    await user.click(inList().getByRole("checkbox", { name: "Select nginx" }));
    await user.keyboard("{Shift>}");
    await user.click(inList().getByRole("checkbox", { name: "Select sshd" }));
    await user.keyboard("{/Shift}");
    expect(inList().getByRole("checkbox", { name: "Select redis-server" })).toBeChecked();
    expect(await screen.findByRole("heading", { name: "3 apps selected" })).toBeInTheDocument();

    await user.click(inList().getByRole("checkbox", { name: "Select all shown apps" }));
    expect(inList().getByRole("checkbox", { name: "Select nginx" })).not.toBeChecked();
    expect(screen.queryByRole("heading", { name: /apps selected/ })).not.toBeInTheDocument();
  });
});

describe("Inspector: one app", () => {
  it("shows the app with its rows: tags and who can reach it once each on the row that names it, and addresses", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const panel = inspector();
    expect(await within(panel).findByRole("heading", { name: /^nginx/ })).toBeInTheDocument();
    expect(within(panel).getByText("pending")).toBeInTheDocument();
    // One section of rows: All ports first. Tag pill of the app; access: direct and through the tag, each once.
    const ports = within(panel).getByRole("heading", { name: "Ports" }).closest("section")!;
    const all = within(ports).getByText("All ports", { selector: ".port-name" }).closest("li")!;
    expect(within(all).getByRole("button", { name: "web" })).toBeInTheDocument();
    expect(within(all).getAllByRole("button", { name: "alice" })).toHaveLength(1);
    expect(within(all).getByRole("button", { name: "Revoke alice" })).toBeInTheDocument();
    expect(within(all).getByRole("button", { name: "Go to tag web" })).toBeInTheDocument();
    // The ports are rows of the same section, without the access of All ports repeated.
    const row = within(ports).getByText("443/tcp").closest("li")!;
    expect(within(ports).getByText("80/tcp")).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "alice" })).not.toBeInTheDocument();
    expect(within(row).getByRole("button", { name: /also reachable by everyone on All ports/ })).toBeInTheDocument();
    // The address is a part of the row, not a section of its own.
    expect(within(panel).queryByRole("heading", { name: "Addresses" })).not.toBeInTheDocument();
    expect(within(all).getByText("Yggdrasil")).toBeInTheDocument();
  });

  it("puts each access on the row that names it", async () => {
    const onlyPort = grantView({ id: "g-80", target: { kind: "app", id: "a1" }, scope: { kind: "port", port: 80, proto: "tcp" }, subject: { kind: "peer", id: "p2" } });
    setup({
      get_app: () => detail(nginx, { grants: [gAlice, onlyPort], access: [access(onlyPort), access(gAlice)] }),
      list_grants: () => [gAlice, onlyPort],
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const ports = (await within(inspector()).findByRole("heading", { name: "Ports" })).closest("section")!;
    const all = within(ports).getByText("All ports", { selector: ".port-name" }).closest("li")!;
    const row80 = within(ports).getByText("80/tcp").closest("li")!;
    expect(all).toHaveTextContent("alice");
    expect(all).not.toHaveTextContent("bob");
    expect(row80).toHaveTextContent("bob");
    expect(row80).not.toHaveTextContent("alice");
  });

  it("shows the address on the row it serves: network, locator with Copy, up or closed; a row without one says so", async () => {
    const mk = (id: string, network_id: string, scope: Scope, addr: string, up = true) =>
      ({ id, app_id: "a1", network_id, scope, locator: { kind: "ipv6" as const, addr }, created_at: "t", reservation_id: null, up, excluded: [], notes: [] });
    const two = {
      ...nginx,
      addresses: [
        mk("x1", "n-ygg", { kind: "all" }, "302::1"),
        mk("x2", "n-ygg", { kind: "port", port: 443, proto: "tcp" }, "302::2", false),
        mk("x3", "n-lan", { kind: "all" }, "fd00::1"),
      ],
    };
    setup({ get_app: () => detail(two) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const ports = (await within(inspector()).findByRole("heading", { name: "Ports" })).closest("section")!;
    const rowOf = (label: string) => within(ports).getByText(label, { selector: ".port-name" }).closest("li")!;
    const all = rowOf("All ports");
    expect(within(all).getByText("302::1")).toBeInTheDocument();
    expect(within(all).getByText("fd00::1")).toBeInTheDocument();
    expect(within(all).getAllByText("up")).toHaveLength(2);
    expect(within(all).getByRole("button", { name: "Copy 302::1" })).toBeInTheDocument();
    const r443 = rowOf("443/tcp");
    expect(within(r443).getByText("302::2")).toBeInTheDocument();
    expect(within(r443).getByText("closed")).toBeInTheDocument();
    // The address is the last part of the card.
    expect(r443.lastElementChild).toHaveClass("port-address");
    expect(within(rowOf("80/tcp")).getByText("Gets an address when access is added.")).toBeInTheDocument();
  });

  it("Copy puts the locator on the clipboard", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const user = userEvent.setup();
    setup();
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Copy 302::2" }));
    expect(writeText).toHaveBeenCalledWith("302::2");
  });

  it("lists the ports an address leaves out and its notes", async () => {
    const withExtras = {
      ...nginx,
      addresses: [
        { id: "x1", app_id: "a1", network_id: "n-ygg", scope: { kind: "all" as const }, locator: { kind: "ipv6" as const, addr: "302::1" }, created_at: "t", reservation_id: null, up: true,
          excluded: [{ start: 9000, end: 9000, proto: "tcp" as const }], notes: ["no client may connect yet"] },
      ],
    };
    setup({ get_app: () => detail(withExtras) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const panel = inspector();
    expect(await within(panel).findByText("Not served here: 9000/tcp (another app is listening on it)")).toBeInTheDocument();
    expect(within(panel).getByText("no client may connect yet")).toBeInTheDocument();
  });

  it("Reserve… asks for a name inline and sends reserve_address through the commit rule", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const ports = (await within(inspector()).findByRole("heading", { name: "Ports" })).closest("section")!;
    const all = within(ports).getByText("All ports", { selector: ".port-name" }).closest("li")!;
    await user.click(within(all).getByRole("button", { name: /^Reserve/ }));
    const form = within(all).getByRole("form", { name: "Reserve address" });
    await user.type(within(form).getByRole("textbox"), "public-web");
    await user.click(within(form).getByRole("button", { name: "Reserve" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "reserve_address", address_id: "a1-y", label: "public-web" }]]));
  });

  it("a row bound to a reservation says where it is reached and links to the Reserved tab", async () => {
    const go = vi.fn();
    const res = mkReservation("r1", "front", [{ kind: "app", app_id: "a1", scope: { kind: "port", port: 443, proto: "tcp" } }]);
    setup({ list_reservations: () => [res] });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />, go);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const ports = (await within(inspector()).findByRole("heading", { name: "Ports" })).closest("section")!;
    const row = within(ports).getByText("443/tcp", { selector: ".port-name" }).closest("li")!;
    expect(row).toHaveTextContent("Reached on reserved address front");
    expect(within(row).getByText("302:ffff::1")).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /^Reserve/ })).not.toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: "Go to reservation front" }));
    expect(go).toHaveBeenCalledWith("reserved", { reservationId: "r1" });
  });

  it("Revoke closes at once, with an Undo toast that puts the grant back", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Revoke alice" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "remove_grant", grant_id: "g-alice" }]]));
    expect(await screen.findByText("Access revoked")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(applied(d)).toHaveLength(2));
    expect(applied(d)[1]).toEqual([
      { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p1" }, confirm_open: true },
    ]);
  });

  it("Keep closed marks the app reviewed through the same rule", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Keep closed" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "review", app_id: "a1", reviewed: true }]]));
  });

  it("Forget asks first", async () => {
    const d = setup({ delete_app: () => saved(null) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Forget app" }));
    expect(d.count("delete_app")).toBe(0);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Forget app" }));
    await waitFor(() => expect(d.last("delete_app")?.args).toEqual({ id: "a1" }));
  });
});

describe("A program that moved", () => {
  const moved = { kind: "update" as const, item: "grant" as const, name: "alice on nginx-old moves to nginx", opens_to_anyone: false, reach: [] };
  // The old entry: same program name, but its executable is gone.
  const old = mkApp("o1", "nginx-old", [80], { process_name: "nginx", exe_missing: true });
  const gone = mkApp("o2", "nginx-gone", [80], { process_name: "nginx", exe_missing: false });

  it("a pending app named like an app with a missing executable offers to take over, after a review", async () => {
    const d = setup({ list_apps: () => [nginx, redis, old], changes: (a) => batch(a.req as ChangesRequest, false, [moved]) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx$/ }));
    const card = await within(inspector()).findByRole("group", { name: "Moved program" });
    expect(card).toHaveTextContent("Looks like nginx-old moved.");
    await user.click(within(card).getByRole("button", { name: "Take over from the old entry" }));
    const review = await within(card).findByRole("region", { name: "Review before applying" });
    expect(applied(d)).toEqual([]);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "move_app", from: "o1", to: "a1", confirm_open: false }]]));
  });

  it("is hidden when the other app's executable is still there, or the app is already reviewed", async () => {
    setup({ list_apps: () => [nginx, redis, gone] });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx$/ }));
    await within(inspector()).findByRole("button", { name: "Keep closed" });
    expect(screen.queryByRole("group", { name: "Moved program" })).not.toBeInTheDocument();
  });

  it("is hidden for an app that was already reviewed", async () => {
    const reviewed = { ...nginx, reviewed: true };
    setup({ list_apps: () => [reviewed, old], get_app: () => detail(reviewed) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx$/ }));
    await within(inspector()).findByRole("button", { name: "Mark pending again" });
    expect(screen.queryByRole("group", { name: "Moved program" })).not.toBeInTheDocument();
  });
});

describe("Transfer access to another app", () => {
  const moved = { kind: "update" as const, item: "grant" as const, name: "alice on nginx moves to redis-server", opens_to_anyone: false, reach: [] };
  async function pickTarget(user: ReturnType<typeof userEvent.setup>, go?: (page: Page, focus?: Focus) => void) {
    renderWithProviders(<AppsPage />, go);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    expect(await within(inspector()).findByText(/Use it when a program was moved or reinstalled/)).toBeInTheDocument();
    await user.click(await within(inspector()).findByRole("button", { name: "Transfer access to another app…" }));
    await user.click(await screen.findByRole("checkbox", { name: "redis-server" }));
  }

  it("always shows the review, even when nobody gains access, and Apply sends move_app", async () => {
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, false, [moved]) });
    const user = userEvent.setup();
    const go = vi.fn();
    await pickTarget(user, go);
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent("alice on nginx moves to redis-server");
    expect(applied(d)).toEqual([]);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "move_app", from: "a1", to: "a2", confirm_open: false }]]));
    // The target is selected afterwards.
    await waitFor(() => expect(go).toHaveBeenCalledWith("apps", { appId: "a2" }));
  });

  it("asks for a confirmation when an Anyone grant moves", async () => {
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [{ ...moved, opens_to_anyone: true }]) });
    const user = userEvent.setup();
    await pickTarget(user);
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    const dialog = await screen.findByRole("dialog");
    expect(applied(d)).toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: "Open it" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "move_app", from: "a1", to: "a2", confirm_open: true }]]));
  });

  it("Cancel in the review sends nothing", async () => {
    const d = setup();
    const user = userEvent.setup();
    await pickTarget(user);
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    await user.click(within(review).getByRole("button", { name: "Cancel" }));
    expect(applied(d)).toEqual([]);
  });
});

describe("Add access", () => {
  async function openForm(user: ReturnType<typeof userEvent.setup>) {
    await user.click(await inList().findByRole("button", { name: "sshd" }));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access to All ports" }));
    return screen.getByRole("form", { name: "Add access" });
  }

  it("a peer chosen in the picker gives a review when it lets somebody in, and Apply sends the grant", async () => {
    const created = { kind: "create" as const, item: "grant" as const, name: "alice to sshd", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" as const }] };
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [created]) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const form = await openForm(user);
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    const review = await within(form).findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent("alice to sshd");
    expect(review).toHaveTextContent("verified by key");
    expect(applied(d)).toEqual([]);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "add_grant", target: { kind: "app", id: "a3" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p1" }, confirm_open: false },
    ]]));
  });

  it("pasting an address creates the peer inline in the same batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const form = await openForm(user);
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.type(screen.getByRole("combobox", { name: "Search Who" }), "10.0.0.7");
    await user.click(await screen.findByRole("option", { name: /New peer from/ }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([
      { op: "create_peer", ref: "$new0", credentials: [{ kind: "ip", value: "10.0.0.7" }] },
      { op: "add_grant", target: { kind: "app", id: "a3" }, subject: { kind: "peer", id: "$new0" } },
    ]);
    expect(applied(d)[0][0]).not.toHaveProperty("label");
  });

  it("Anyone asks for the confirmation before anything is saved, and sends it", async () => {
    const opening = { kind: "create" as const, item: "grant" as const, name: "Anyone to sshd", opens_to_anyone: true };
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [opening]) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const form = await openForm(user);
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: /Anyone/ }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await user.click(within(await within(form).findByRole("region", { name: "Review before applying" })).getByRole("button", { name: "Apply" }));
    expect(applied(d)).toEqual([]);
    await user.click(within(await screen.findByRole("dialog", { name: /Open to anyone/ })).getByRole("button", { name: "Open it" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "add_grant", subject: { kind: "anyone" }, confirm_open: true }]);
  });

  it("limits to a chosen port and networks", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access to 443/tcp" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "bob" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByText("Limit to networks (optional)"));
    await user.click(within(form).getByRole("checkbox", { name: "LAN" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "port", port: 443, proto: "tcp" }, network_id: "n-lan", subject: { kind: "peer", id: "p2" }, confirm_open: false },
    ]);
  });
});

describe("Tags", () => {
  it("one tag: members, patterns, who can reach it; no modal and no separate panel", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await findTagRow("web"));
    const panel = inspector();
    expect(await within(panel).findByRole("heading", { name: "web" })).toBeInTheDocument();
    expect(within(panel).getByLabelText("Name")).toHaveValue("web");
    expect(within(panel).getByLabelText(/Auto-match patterns/)).toHaveValue("nginx*");
    const members = within(panel).getByRole("heading", { name: /Members \(2\)/ }).closest("section")!;
    expect(within(members).getByText("nginx")).toBeInTheDocument();
    expect(within(members).getByText("redis-server")).toBeInTheDocument();
    expect(within(members).getAllByText(/· All ports/)).toHaveLength(2);
    const who = within(panel).getByRole("heading", { name: /Who can reach its members/ }).closest("section")!;
    expect(within(who).getByRole("button", { name: "bob" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("members are changed in a picker: removing applies at once with Undo, adding to a tag with grants shows who gains access", async () => {
    const joining = { kind: "create" as const, item: "tag_member" as const, name: "sshd in tag web", detail: "reachable by bob", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" as const }] };
    const d = setup({ changes: (a) => ((a.req as ChangesRequest).ops[0].op === "add_tag_member" ? batch(a.req as ChangesRequest, true, [joining]) : batch(a.req as ChangesRequest)) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await findTagRow("web"));
    // Pick an app, then its row.
    await user.click(await within(inspector()).findByRole("button", { name: "Add or remove members" }));
    await user.click(screen.getByRole("checkbox", { name: "redis-server" }));
    const rows = within(await within(inspector()).findByRole("group", { name: "Rows of redis-server in web" }));
    expect(rows.getByRole("button", { name: "All ports" })).toHaveAttribute("aria-pressed", "true");
    await user.click(rows.getByRole("button", { name: "All ports" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "remove_tag_member", tag_id: "t1", app_id: "a2", scope: { kind: "all" } }]]));
    expect(await screen.findByRole("button", { name: "Undo" })).toBeInTheDocument();

    await user.click(within(inspector()).getByRole("button", { name: "Add or remove members" }));
    await user.click(screen.getByRole("checkbox", { name: "sshd" }));
    await user.click(within(await within(inspector()).findByRole("group", { name: "Rows of sshd in web" })).getByRole("button", { name: "All ports" }));
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent("reachable by bob");
    expect(applied(d)).toHaveLength(1);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(2));
    expect(applied(d)[1]).toEqual([{ op: "add_tag_member", tag_id: "t1", app_id: "a3", scope: { kind: "all" }, confirm_open: false }]);
  });

  it("saving patterns that would open apps to anyone asks first", async () => {
    let calls = 0;
    const d = setup({
      update_tag: (a) => {
        calls++;
        if (!(a.req as { confirm_open: boolean }).confirm_open) throw { code: "confirmation_required", message: "confirm" };
        return saved(web);
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await findTagRow("web"));
    const patterns = await within(inspector()).findByLabelText(/Auto-match patterns/);
    await user.clear(patterns);
    await user.type(patterns, "ngi*{Enter}x");
    await user.click(within(inspector()).getByRole("button", { name: "Save tag" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Save and open" }));
    await waitFor(() => expect(calls).toBe(2));
    expect(d.last("update_tag")?.args).toMatchObject({ id: "t1", req: { patterns: ["ngi*", "x"], confirm_open: true } });
  });

  it("New tag opens a form in the inspector and creates through the batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: "New tag" }));
    expect(await screen.findByRole("heading", { name: "New tag" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Tag name"), "staging");
    await user.type(screen.getByLabelText(/Auto-match patterns/), "stg*");
    await user.click(screen.getByRole("button", { name: "Create tag" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "create_tag", label: "staging", patterns: ["stg*"] }]]));
  });
});

describe("Inspector: several tags", () => {
  it("shows the access they share or only some have, adds access for all, and deletes them after asking once", async () => {
    const toData = grantView({ id: "g-data", target: { kind: "tag", id: "t2" }, subject: { kind: "peer", id: "p2" } });
    const d = setup({ delete_tag: () => saved(null) }, [web, data], [gTag, toData]);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select web" }));
    await user.click(inList().getByRole("checkbox", { name: "Select data" }));
    const panel = within(await screen.findByRole("region", { name: "Details" }));
    expect(await panel.findByRole("heading", { name: "2 tags selected" })).toBeInTheDocument();
    expect(panel.getByText("all 2 tags")).toBeInTheDocument();

    await user.click(panel.getByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "All ports" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].map((o) => (o as { target: { id: string } }).target.id)).toEqual(["t1", "t2"]);

    await user.click(panel.getByRole("button", { name: "Delete 2 tags" }));
    expect(d.count("delete_tag")).toBe(0);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete tags" }));
    await waitFor(() => expect(d.count("delete_tag")).toBe(2));
  });
});

describe("Inspector: several apps", () => {
  async function selectThree(user: ReturnType<typeof userEvent.setup>) {
    for (const n of ["nginx", "redis-server", "sshd"]) await user.click(await inList().findByRole("checkbox", { name: `Select ${n}` }));
    return screen.findByRole("heading", { name: "3 apps selected" });
  }

  it("shows the tags some or all have as mixed, and a tag picked for all adds only where it is missing", async () => {
    const d = setup({}, [web, data], [gAlice, gLan, gTag]);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await selectThree(user);
    const panel = inspector();
    expect(within(panel).getByRole("button", { name: "web 2/3" })).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "data 1/3" })).toBeInTheDocument();
    await user.click(within(panel).getByRole("button", { name: "Add or remove tags" }));
    const box = screen.getByRole("checkbox", { name: /^web/ }) as HTMLInputElement;
    expect(box.indeterminate).toBe(true);
    await user.click(box);
    // The tag has grants, so the batch is first checked; with no change in reach it applies.
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "add_tag_member", tag_id: "t1", app_id: "a3", scope: { kind: "all" }, confirm_open: false }]]));
  });

  it("a name that is no tag yet is created and applied to every selected app", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await selectThree(user);
    await user.click(within(inspector()).getByRole("button", { name: "Add or remove tags" }));
    await user.type(screen.getByRole("combobox", { name: "Search Tags" }), "prod{Enter}");
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "create_tag", ref: "$tag", label: "prod", patterns: [] },
      { op: "add_tag_member", tag_id: "$tag", app_id: "a1", scope: { kind: "all" }, confirm_open: false },
      { op: "add_tag_member", tag_id: "$tag", app_id: "a2", scope: { kind: "all" }, confirm_open: false },
      { op: "add_tag_member", tag_id: "$tag", app_id: "a3", scope: { kind: "all" }, confirm_open: false },
    ]);
  });

  it("shows the access that all or only some have, and Revoke removes every grant behind it", async () => {
    const both = [
      grantView({ id: "r1", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p1" } }),
      grantView({ id: "r2", target: { kind: "app", id: "a2" }, subject: { kind: "peer", id: "p1" } }),
      grantView({ id: "r3", target: { kind: "app", id: "a3" }, subject: { kind: "peer", id: "p1" } }),
      grantView({ id: "r4", target: { kind: "app", id: "a3" }, subject: { kind: "peer", id: "p2" } }),
    ];
    const d = setup({}, [], both);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await selectThree(user);
    const who = within(inspector()).getByRole("heading", { name: "Who can reach them" }).closest("section")!;
    expect(within(who).getByText("all 3 apps")).toBeInTheDocument();
    expect(within(who).getByText("1 of 3 apps")).toBeInTheDocument();
    await user.click(within(who).getByRole("button", { name: "Revoke alice" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "remove_grant", grant_id: "r1" }, { op: "remove_grant", grant_id: "r2" }, { op: "remove_grant", grant_id: "r3" },
    ]]));
  });

  it("adds access for all of them in one batch, and marks the pending ones reviewed", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await selectThree(user);
    await user.click(within(inspector()).getByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "group team" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "All ports" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].map((o) => (o as { target: { id: string } }).target.id)).toEqual(["a1", "a2", "a3"]);

    await user.click(within(inspector()).getByRole("button", { name: "Mark reviewed (1)" }));
    await waitFor(() => expect(applied(d)).toHaveLength(2));
    expect(applied(d)[1]).toEqual([{ op: "review", app_id: "a1", reviewed: true }]);
  });

  it("has no bulk bar and no dialog of its own", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await selectThree(user);
    expect(screen.queryByRole("toolbar", { name: "Bulk actions" })).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("Subject columns", () => {
  // A row's name is its label and its hint, so "All" is "All5 columns".
  const columnBox = (name: RegExp | string) => screen.getByRole("checkbox", { name: name === "All" ? /^All/ : name });
  const addColumns = async (user: ReturnType<typeof userEvent.setup>, ...names: string[]) => {
    await user.click(await screen.findByRole("button", { name: /^Columns/ }));
    for (const n of names) await user.click(columnBox(n));
    await user.keyboard("{Escape}");
  };

  it("has none to start with, and no network selector", async () => {
    setup();
    renderWithProviders(<AppsPage />);
    await inList().findByRole("button", { name: /^nginx/ });
    expect(inList().queryByRole("columnheader", { name: "alice" })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Network" })).not.toBeInTheDocument();
  });

  it("adds and removes a subject as a column; the network selector appears with the first one", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "alice");
    expect(inList().getByRole("columnheader", { name: "alice" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Network" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Columns (1)" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Columns (1)" }));
    await user.click(columnBox("alice"));
    await user.keyboard("{Escape}");
    expect(inList().queryByRole("columnheader", { name: "alice" })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Network" })).not.toBeInTheDocument();
  });

  it("All adds every subject: groups, peers, Anyone and Everyone on each LAN", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "All");
    for (const label of ["group team", "alice", "bob", "Anyone", "Everyone on LAN"]) {
      expect(inList().getByRole("columnheader", { name: label })).toBeInTheDocument();
    }
    await user.click(screen.getByRole("button", { name: "Columns (5)" }));
    await user.click(columnBox(/^All/));
    await user.keyboard("{Escape}");
    expect(inList().queryByRole("columnheader", { name: "alice" })).not.toBeInTheDocument();
  });

  it("remembers the chosen columns for the next visit, and works when storage is blocked", async () => {
    setup();
    const user = userEvent.setup();
    const first = renderWithProviders(<AppsPage />);
    await addColumns(user, "bob");
    expect(JSON.parse(storage.getItem("socketguard.columns")!)).toEqual(["peer:p2"]);
    first.unmount();
    renderWithProviders(<AppsPage />);
    expect(await inList().findByRole("columnheader", { name: "bob" })).toBeInTheDocument();
  });

  it("works for the session when storage is blocked", async () => {
    vi.stubGlobal("localStorage", {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
    });
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "bob");
    expect(inList().getByRole("columnheader", { name: "bob" })).toBeInTheDocument();
    // Leave nothing behind for the other tests.
    await user.click(screen.getByRole("button", { name: "Columns (1)" }));
    await user.click(columnBox("bob"));
  });

  it("cells show granted, partial and inherited, and nothing else; the origin is in the tooltip", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "alice", "bob");
    const granted = await inList().findByRole("button", { name: "nginx – alice: granted" });
    expect(granted).toHaveAttribute("title", "Granted");
    expect(inList().getByRole("button", { name: "redis-server – alice: granted on some networks" })).toHaveAttribute("title", "Granted on LAN only");
    const inherited = inList().getByRole("button", { name: "nginx – bob: inherited" });
    expect(inherited).toHaveAttribute("title", "Inherited through tag web");
    expect(inList().getByRole("button", { name: "sshd – bob: no access" })).toBeInTheDocument();
    // Display only: nothing is staged, no bar, no preview.
    await user.click(granted);
    expect(screen.queryByRole("region", { name: "Staged changes" })).not.toBeInTheDocument();
    expect(requests(d)).toHaveLength(0);
  });

  it("the network selector scopes the cells", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "alice");
    await inList().findByRole("button", { name: "redis-server – alice: granted on some networks" });
    await user.selectOptions(screen.getByRole("combobox", { name: "Network" }), "LAN");
    expect(await inList().findByRole("button", { name: "redis-server – alice: granted" })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Network" }), "Yggdrasil");
    expect(await inList().findByRole("button", { name: "redis-server – alice: no access" })).toBeInTheDocument();
  });

  it("the inspector is a narrow strip until a row or a cell is clicked; a cell opens it at that subject's access", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "alice");
    expect(screen.getByRole("button", { name: "Show details" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /^nginx/ })).not.toBeInTheDocument();
    await user.click(await inList().findByRole("button", { name: "nginx – alice: granted" }));
    const panel = inspector();
    expect(await within(panel).findByRole("heading", { name: /^nginx/ })).toBeInTheDocument();
    const marked = panel.querySelector(".access-highlight");
    expect(marked).toHaveTextContent("alice");
    // It can be hidden again, and a row click brings it back.
    await user.click(within(panel).getByRole("button", { name: "Hide details" }));
    expect(screen.getByRole("button", { name: "Show details" })).toBeInTheDocument();
    await user.click(inList().getByRole("button", { name: "sshd" }));
    expect(await within(inspector()).findByRole("heading", { name: "sshd" })).toBeInTheDocument();
  });

  it("an app's ports can be expanded to see their cells", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await addColumns(user, "alice");
    await user.click(await inList().findByRole("button", { name: "Expand ports of nginx" }));
    expect(inList().getByRole("button", { name: "80/tcp – alice: inherited" })).toBeInTheDocument();
  });
});

describe("Add access: what to open", () => {
  async function openNginx(user: ReturnType<typeof userEvent.setup>) {
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access to All ports" }));
    return screen.getByRole("form", { name: "Add access" });
  }
  async function chooseBob(user: ReturnType<typeof userEvent.setup>, form: HTMLElement) {
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "bob" }));
    await user.keyboard("{Escape}");
  }

  it("preselects nothing when it is not opened from a row: something must be chosen before the form is ready", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await findTagRow("web"));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    const chips = within(within(form).getByRole("group", { name: "What to open" }));
    for (const name of ["All ports", "80/tcp", "443/tcp"]) expect(chips.getByRole("button", { name })).toHaveAttribute("aria-pressed", "false");
    expect(within(form).getByText("Choose what to open")).toBeInTheDocument();
    await chooseBob(user, form);
    expect(within(form).getByRole("button", { name: "Add access" })).toBeDisabled();
    await user.click(chips.getByRole("button", { name: "80/tcp" }));
    expect(within(form).queryByText("Choose what to open")).not.toBeInTheDocument();
    expect(within(form).getByRole("button", { name: "Add access" })).toBeEnabled();
    expect(applied(d)).toEqual([]);
  });

  it("All ports and the narrower chips exclude each other; several ports make one grant each", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const form = await openNginx(user);
    const chips = within(within(form).getByRole("group", { name: "What to open" }));
    // Opened from the All ports row: only that is chosen.
    expect(chips.getByRole("button", { name: "All ports" })).toHaveAttribute("aria-pressed", "true");
    await chooseBob(user, form);
    await user.click(chips.getByRole("button", { name: "80/tcp" }));
    expect(chips.getByRole("button", { name: "All ports" })).toHaveAttribute("aria-pressed", "false");
    await user.click(chips.getByRole("button", { name: "All ports" }));
    expect(chips.getByRole("button", { name: "80/tcp" })).toHaveAttribute("aria-pressed", "false");
    await user.click(chips.getByRole("button", { name: "80/tcp" }));
    await user.click(chips.getByRole("button", { name: "443/tcp" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].map((o) => (o as { scope: unknown }).scope)).toEqual([{ kind: "port", port: 80, proto: "tcp" }, { kind: "port", port: 443, proto: "tcp" }]);
  });

  it("a port row has its own Add access with that port chosen", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(inspector()).findByRole("button", { name: "Add access to 443/tcp" }));
    const form = screen.getByRole("form", { name: "Add access" });
    const chips = within(within(form).getByRole("group", { name: "What to open" }));
    expect(chips.getByRole("button", { name: "443/tcp" })).toHaveAttribute("aria-pressed", "true");
    expect(chips.getByRole("button", { name: "80/tcp" })).toHaveAttribute("aria-pressed", "false");
    expect(chips.getByRole("button", { name: "All ports" })).toHaveAttribute("aria-pressed", "false");
    await chooseBob(user, form);
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "port", port: 443, proto: "tcp" }, subject: { kind: "peer", id: "p2" }, confirm_open: false },
    ]);
    // Cancel closes it again.
    await user.click(within(inspector()).getByRole("button", { name: "Add access to 80/tcp" }));
    await user.click(within(screen.getByRole("form", { name: "Add access" })).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("form", { name: "Add access" })).not.toBeInTheDocument();
  });

  it("pasting several values makes one new peer per value, without a name", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const form = await openNginx(user);
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("combobox", { name: "Search Who" }));
    await user.paste("10.0.0.7 10.0.0.8");
    await user.click(await screen.findByRole("option", { name: /2 new peers from/ }));
    await user.keyboard("{Escape}");
    const chosen = within(form).getByRole("list", { name: "Chosen subjects" });
    expect(within(chosen).getAllByRole("listitem")).toHaveLength(2);
    expect(within(chosen).getByText("10.0.0.7")).toBeInTheDocument();
    expect(within(chosen).getByText("10.0.0.8")).toBeInTheDocument();
    expect(within(form).queryByLabelText(/Label for new peer/)).not.toBeInTheDocument();
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    const ops = applied(d)[0];
    expect(ops.map((o) => o.op)).toEqual(["create_peer", "create_peer", "add_grant", "add_grant"]);
    expect(ops[0]).toEqual({ op: "create_peer", ref: "$new0", credentials: [{ kind: "ip", value: "10.0.0.7", label: null }] });
    expect(ops[1]).toEqual({ op: "create_peer", ref: "$new1", credentials: [{ kind: "ip", value: "10.0.0.8", label: null }] });
  });
});

describe("Tag and close controls", () => {
  it("every row has a + pill after its tags, a port row with the port's tags", async () => {
    const portTag = mkTag("t3", "frontend", []);
    portTag.members = [{ app_id: "a1", scope: { kind: "port", port: 443, proto: "tcp" } }];
    setup({}, [web, data, portTag]);
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("button", { name: /^nginx/ }));
    const panel = inspector();
    const plus = await within(panel).findByRole("button", { name: "Add or remove tags of All ports" });
    expect(plus).toHaveTextContent("+");
    expect(plus).toHaveClass("tag-pill");
    expect(within(panel).queryByRole("button", { name: "Tags…" })).not.toBeInTheDocument();
    const row = within(panel).getByText("443/tcp").closest("li")!;
    expect(within(row).getByRole("button", { name: "frontend" })).toHaveClass("tag-pill");
    const portPlus = within(row).getByRole("button", { name: "Add or remove tags of 443/tcp" });
    expect(portPlus).toHaveClass("tag-pill", "tag-pill-add");
    await user.click(portPlus);
    expect(await screen.findByRole("combobox", { name: "Search Tags of 443/tcp" })).toBeInTheDocument();
  });

  it("the inspector's × hides it and keeps the selection; a click or a tick shows it again", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select nginx" }));
    await user.click(inList().getByRole("checkbox", { name: "Select sshd" }));
    expect(await screen.findByRole("heading", { name: "2 apps selected" })).toBeInTheDocument();
    await user.click(within(inspector()).getByRole("button", { name: "Close details" }));
    expect(screen.queryByRole("region", { name: "Details" })).not.toBeInTheDocument();
    expect(inList().getByRole("checkbox", { name: "Select nginx" })).toBeChecked();
    expect(inList().getByRole("checkbox", { name: "Select sshd" })).toBeChecked();
    await user.click(inList().getByRole("checkbox", { name: "Select redis-server" }));
    expect(await screen.findByRole("heading", { name: "3 apps selected" })).toBeInTheDocument();
    await user.click(within(inspector()).getByRole("button", { name: "Close details" }));
    await user.click(inList().getByRole("button", { name: "sshd" }));
    expect(await within(inspector()).findByRole("heading", { name: "sshd" })).toBeInTheDocument();
  });
});

describe("Addresses on the Local network", () => {
  const addr = (id: string, network_id: string, addr: string, up: boolean) =>
    ({ id, app_id: "l1", network_id, scope: { kind: "all" as const }, locator: { kind: "ipv6" as const, addr }, created_at: "2026-01-01T00:00:00Z", reservation_id: null, up, excluded: [], notes: [] });
  const open = async (app: ReturnType<typeof mkApp>) => {
    mockDaemon({ list_apps: () => [app], get_app: () => detail(app) });
    renderWithProviders(<AppsPage />);
    await userEvent.click(await inList().findByRole("button", { name: /^mydb/ }));
    const row = (await within(inspector()).findByText("All ports", { selector: ".port-name" })).closest("li")!;
    return within(row);
  };

  it("is 'this machine only': muted, with Copy, no up/closed badge and no Reserve", async () => {
    const all = await open(mkApp("l1", "mydb", [5432], { addresses: [addr("l-lo", "n-local", "::1", true)] }));
    const line = (await all.findByText("Local")).closest(".address-row") as HTMLElement;
    expect(line).toHaveClass("muted");
    expect(within(line).getByText("this machine only")).toBeInTheDocument();
    expect(within(line).getByRole("button", { name: "Copy ::1" })).toBeInTheDocument();
    expect(all.queryByText("up")).not.toBeInTheDocument();
    expect(all.queryByText("closed")).not.toBeInTheDocument();
    expect(all.queryByRole("button", { name: /^Reserve/ })).not.toBeInTheDocument();
  });

  it("a normal network address keeps its badge and Reserve…", async () => {
    const all = await open(mkApp("l1", "mydb", [5432], { addresses: [addr("l-lo", "n-local", "::1", true), addr("l-y", "n-ygg", "302::9", true)] }));
    expect(await all.findByText("up")).toBeInTheDocument();
    expect(all.getByText("this machine only")).toBeInTheDocument();
    expect(all.getAllByRole("button", { name: /^Reserve/ })).toHaveLength(1);
    expect(all.getByRole("button", { name: "Reserve Yggdrasil address" })).toBeInTheDocument();
  });
});
