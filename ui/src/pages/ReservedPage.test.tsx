// The Reserved tab (ADR 0047): reservations with their addresses, rows and conflicts.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ReservedPage from "./ReservedPage";
import type { ChangesRequest, GrantView, Network } from "../api";
import {
  batch, detail, grantView, mkApp, mkPeer, mkReservation, memoryStorage, mockDaemon, networks, renderWithProviders, saved,
} from "../test/helpers";

const nginx = mkApp("a1", "nginx", [80, 443]);
const caddy = mkApp("a2", "caddy", [443]);
const sshd = mkApp("a3", "sshd", [22]);
const apps = [nginx, caddy, sshd];

const alice = mkPeer("p1", "alice");
const bob = mkPeer("p2", "bob");

const tor: Network = { id: "n-tor", kind: "tor", name: "Tor", interface: null, grants_apply: true, status: { state: "up" } };
const TOR_NOTE = "bound to reservation front: on Tor grant the reservation as a whole";

const gRes = grantView({ id: "g-res", target: { kind: "reservation", id: "r1" }, subject: { kind: "peer", id: "p1" } });
const gRow = grantView({
  id: "g-443", target: { kind: "app", id: "a1" }, scope: { kind: "port", port: 443, proto: "tcp" }, subject: { kind: "peer", id: "p2" },
  reach: [{ network_id: "n-ygg", reach: "verified" }, { network_id: "n-tor", reach: "not_reachable", note: TOR_NOTE }],
});
const gOpen = grantView({ id: "g-open", target: { kind: "reservation", id: "r3" }, subject: { kind: "anyone" }, reach: [{ network_id: "n-lan", reach: "open" }] });

const front = mkReservation(
  "r1", "front",
  [{ kind: "app", app_id: "a1", scope: { kind: "port", port: 443, proto: "tcp" } }, { kind: "app", app_id: "a2", scope: { kind: "port", port: 443, proto: "tcp" } }],
  { grants: [gRes], conflicts: [{ ports: { start: 443, end: 443, proto: "tcp" }, bindings: ["r1-b0", "r1-b1"], served_app: "a1" }] },
);
const ops = mkReservation("r2", "ops", [{ kind: "app", app_id: "a3", scope: { kind: "port", port: 22, proto: "tcp" } }], { addresses: [] });
const open = mkReservation("r3", "public", [], { grants: [gOpen] });

const requests = (d: ReturnType<typeof mockDaemon>) => d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest);
const applied = (d: ReturnType<typeof mockDaemon>) => requests(d).filter((r) => !r.dry_run).map((r) => r.ops);

function setup(over: Parameters<typeof mockDaemon>[0] = {}, grants: GrantView[] = [gRes, gRow, gOpen]) {
  return mockDaemon({
    list_apps: () => apps,
    get_app: (a) => detail(apps.find((x) => x.id === a.id)!),
    list_peers: () => [alice, bob],
    list_grants: () => grants,
    list_networks: () => [...networks, tor],
    list_reservations: () => [front, ops, open],
    changes: (a) => batch(a.req as ChangesRequest),
    ...over,
  });
}

const inList = () => within(screen.getByRole("table", { name: "Reservations" }));
const inspector = () => screen.getByRole("region", { name: "Details" });
const rowOf = (label: string) => within(inspector()).getByText(label, { selector: ".port-name" }).closest("li")!;
async function openReservation(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await inList().findByRole("button", { name: new RegExp(`^${name}`) }));
  return within(await within(inspector()).findByRole("complementary", { name: "Reservation details" }));
}

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the list", () => {
  it("has one row per reservation: what it serves, its addresses, its access and a conflict badge", async () => {
    setup();
    renderWithProviders(<ReservedPage />);
    const rowFront = (await inList().findByRole("button", { name: /^front/ })).closest("tr")!;
    expect(rowFront).toHaveTextContent("nginx 443/tcp, caddy 443/tcp");
    expect(rowFront).toHaveTextContent("Yggdrasil: 302:ffff::1 up");
    expect(rowFront).toHaveTextContent("1 grant, 1 on single ports");
    expect(rowFront).toHaveTextContent("port conflict");
    const rowOps = inList().getByRole("button", { name: /^ops/ }).closest("tr")!;
    expect(rowOps).toHaveTextContent("none yet");
    expect(rowOps).toHaveTextContent("no grants");
    expect(rowOps).not.toHaveTextContent("port conflict");
    expect(inList().getByRole("button", { name: /^public/ }).closest("tr")).toHaveTextContent("open to anyone");
  });

  it("filters by name and by what it serves; has select-all and a checkbox per row", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await inList().findByRole("button", { name: /^front/ });
    await user.type(screen.getByRole("searchbox", { name: "Filter reservations" }), "sshd");
    expect(inList().queryByRole("button", { name: /^front/ })).not.toBeInTheDocument();
    expect(inList().getByRole("button", { name: /^ops/ })).toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox", { name: "Filter reservations" }));
    await user.click(inList().getByRole("checkbox", { name: "Select all shown reservations" }));
    expect(inList().getByRole("checkbox", { name: "Select front" })).toBeChecked();
  });

  it("explains in one sentence what a reserved address is when there is none", async () => {
    setup({ list_reservations: () => [] });
    renderWithProviders(<ReservedPage />);
    expect(await screen.findByText("A named address that stays the same and can front ports of several apps.")).toBeInTheDocument();
  });
});

describe("one reservation", () => {
  it("shows its addresses, its own All ports row and one card per bound row", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    const panel = await openReservation(user, "front");
    const addresses = panel.getByRole("heading", { name: "Addresses" }).closest("section")!;
    expect(within(addresses).getByText("302:ffff::1")).toBeInTheDocument();
    expect(within(addresses).getByText("up")).toBeInTheDocument();
    expect(within(addresses).getByRole("button", { name: "Copy 302:ffff::1" })).toBeInTheDocument();
    const labels = [...inspector().querySelectorAll(".port-name")].map((e) => e.textContent);
    expect(labels).toEqual(["All ports", "nginx · 443/tcp", "caddy · 443/tcp"]);
    // The reservation's All ports lists the grants on the reservation; Add access targets it.
    expect(rowOf("All ports")).toHaveTextContent("alice");
    // Bound rows list the grants of the app row, and have neither tags nor an address part.
    expect(rowOf("nginx · 443/tcp")).toHaveTextContent("bob");
    expect(rowOf("nginx · 443/tcp")).not.toHaveTextContent("alice");
    for (const l of labels.slice(1)) {
      expect(rowOf(l!).querySelector(".port-tags")).toBeNull();
      expect(rowOf(l!).querySelector(".port-address")).toBeNull();
    }
    expect(within(rowOf("nginx · 443/tcp")).getByRole("button", { name: "Revoke bob 443/tcp" })).toBeInTheDocument();
  });

  it("a reservation without an address says it gets one when access is added", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    const panel = await openReservation(user, "ops");
    expect(panel.getByText("Gets an address when access is added.")).toBeInTheDocument();
  });

  it("lists each port conflict and marks the affected cards", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    expect(within(inspector()).getByRole("alert")).toHaveTextContent("443/tcp: nginx and caddy — served: nginx");
    expect(within(rowOf("nginx · 443/tcp")).getByText("port conflict")).toBeInTheDocument();
    expect(within(rowOf("caddy · 443/tcp")).getByText("port conflict")).toBeInTheDocument();
  });

  it("a conflict nobody is served on says it is closed until one of them listens", async () => {
    const closed = mkReservation("r1", "front", front.bindings.map((b) => b.target), { conflicts: [{ ...front.conflicts[0], served_app: null }] });
    setup({ list_reservations: () => [closed] });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    expect(within(inspector()).getByRole("alert")).toHaveTextContent("443/tcp: nginx and caddy — closed until one of them listens");
  });

  it("a grant on the reservation's All ports is sent with target reservation and scope All", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    await user.click(within(rowOf("All ports")).getByRole("button", { name: "Add access to All ports" }));
    const form = screen.getByRole("form", { name: "Add access" });
    expect([...within(form).getByRole("group", { name: "What to open" }).querySelectorAll("button")].map((b) => b.textContent)).toEqual(["All ports"]);
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "bob" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "add_grant", target: { kind: "reservation", id: "r1" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p2" }, confirm_open: false },
    ]]));
  });

  it("the review of an access added on a bound row shows the Tor note of the daemon", async () => {
    const created = {
      kind: "create" as const, item: "grant" as const, name: "bob to nginx 443/tcp", opens_to_anyone: false,
      reach: [{ network_id: "n-ygg", reach: "verified" as const }, { network_id: "n-tor", reach: "not_reachable" as const, note: TOR_NOTE }],
    };
    setup({ changes: (a) => batch(a.req as ChangesRequest, true, [created]) });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    await user.click(within(rowOf("nginx · 443/tcp")).getByRole("button", { name: "Add access to nginx · 443/tcp" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("button", { name: "Choose who…" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    const review = await within(form).findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent(`On Tor: not reachable — ${TOR_NOTE}`);
  });

  it("shows the Tor note on the bound row whose grantee is not reachable there", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    expect(rowOf("nginx · 443/tcp")).toHaveTextContent(`On Tor: not reachable — ${TOR_NOTE}`);
    expect(rowOf("caddy · 443/tcp")).not.toHaveTextContent("On Tor");
  });
});

describe("New reservation", () => {
  it("asks for a name and creates it with the create_reservation batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await user.click(await screen.findByRole("button", { name: "New reservation" }));
    const form = screen.getByRole("form", { name: "New reservation" });
    await user.type(within(form).getByRole("textbox"), "web-front");
    await user.click(within(form).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "create_reservation", label: "web-front", bindings: [], confirm_open: false }]]));
  });
});

describe("Add ports", () => {
  const pick = async (user: ReturnType<typeof userEvent.setup>, name: string, row: RegExp) => {
    const panel = await openReservation(user, name);
    await user.click(panel.getByRole("button", { name: "Add ports" }));
    await user.click(await screen.findByRole("checkbox", { name: row }));
    return panel;
  };

  it("lists the rows of every app by app, and disables the rows bound elsewhere with the reservation", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    const panel = await openReservation(user, "front");
    await user.click(panel.getByRole("button", { name: "Add ports" }));
    const list = within(await screen.findByRole("listbox", { name: "Ports of front" }));
    for (const heading of ["nginx", "caddy", "sshd"]) expect(list.getByText(heading, { selector: ".picker-heading" })).toBeInTheDocument();
    const ssh22 = list.getByRole("checkbox", { name: /^22\/tcp/ });
    expect(ssh22).toBeDisabled();
    expect(ssh22.closest("label")).toHaveTextContent("in ops");
    expect(list.getByRole("checkbox", { name: /^80\/tcp/ })).toBeEnabled();
    // 443/tcp of nginx and of caddy are both bound here.
    const here = list.getAllByRole("checkbox", { name: /^443\/tcp/ }).filter((b) => b.closest("label")?.textContent?.includes("bound here"));
    expect(here).toHaveLength(2);
    for (const box of here) expect(box).toBeDisabled();
  });

  it("applies at once when the reservation has no grants to let more in", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await pick(user, "ops", /^80\/tcp/);
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "add_binding", reservation_id: "r2", target: { kind: "app", app_id: "a1", scope: { kind: "port", port: 80, proto: "tcp" } }, confirm_open: false },
    ]]));
  });

  it("shows a review first when the reservation has grants that would let somebody in", async () => {
    const reach = { kind: "create" as const, item: "binding" as const, name: "nginx 80/tcp in front", detail: "reachable by alice", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" as const }] };
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [reach]) });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await pick(user, "front", /^80\/tcp/);
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    expect(review).toHaveTextContent("reachable by alice");
    expect(applied(d)).toEqual([]);
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
  });

  it("asks before opening to Anyone", async () => {
    const reach = { kind: "create" as const, item: "binding" as const, name: "nginx 80/tcp in public", opens_to_anyone: true, reach: [{ network_id: "n-lan", reach: "open" as const }] };
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [reach]) });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await pick(user, "public", /^80\/tcp/);
    const review = await within(inspector()).findByRole("region", { name: "Review before applying" });
    await user.click(within(review).getByRole("button", { name: "Apply" }));
    const dialog = await screen.findByRole("dialog");
    expect(applied(d)).toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: "Open it" }));
    await waitFor(() => expect(applied(d)[0][0]).toMatchObject({ op: "add_binding", reservation_id: "r3", confirm_open: true }));
  });
});

describe("Remove from reservation", () => {
  it("removes the binding at once and Undo binds the row again", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    await user.click(within(rowOf("caddy · 443/tcp")).getByRole("button", { name: "Remove caddy · 443/tcp from reservation" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "remove_binding", reservation_id: "r1", binding_id: "r1-b1" }]]));
    await user.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(applied(d)).toHaveLength(2));
    expect(applied(d)[1]).toEqual([
      { op: "add_binding", reservation_id: "r1", target: { kind: "app", app_id: "a2", scope: { kind: "port", port: 443, proto: "tcp" } }, confirm_open: true },
    ]);
  });

  it("a tag binding shows each member row via the tag", async () => {
    const tagged = mkReservation("r1", "front", [{ kind: "tag", tag_id: "t1" }]);
    setup({
      list_reservations: () => [tagged],
      list_tags: () => [{ id: "t1", label: "web", patterns: [], excluded: [], created_at: "t", members: [{ app_id: "a1", scope: { kind: "all" } }, { app_id: "a3", scope: { kind: "all" } }] }],
    });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await openReservation(user, "front");
    expect(rowOf("nginx · All ports")).toHaveTextContent("via tag web");
    expect(rowOf("sshd · All ports")).toHaveTextContent("via tag web");
    expect(within(rowOf("sshd · All ports")).getByRole("button", { name: "Remove tag web from reservation" })).toBeInTheDocument();
  });
});

describe("Release", () => {
  it("asks first and says what happens to the addresses and the bound ports", async () => {
    const d = setup({ release_reservation: () => saved(null) });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    const panel = await openReservation(user, "front");
    await user.click(panel.getByRole("button", { name: "Release reservation" }));
    expect(d.count("release_reservation")).toBe(0);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("addresses are given up");
    expect(dialog).toHaveTextContent("get their own addresses again");
    await user.click(within(dialog).getByRole("button", { name: "Release reservation" }));
    await waitFor(() => expect(d.last("release_reservation")?.args).toEqual({ id: "r1" }));
  });

  it("several selected: Release N", async () => {
    const d = setup({ release_reservation: () => saved(null) });
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select front" }));
    await user.click(inList().getByRole("checkbox", { name: "Select ops" }));
    await user.click(await screen.findByRole("button", { name: "Release 2" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Release reservations" }));
    await waitFor(() => expect(d.calls.filter((c) => c.cmd === "release_reservation").map((c) => c.args.id)).toEqual(["r1", "r2"]));
  });
});

describe("Wording", () => {
  const banned = /whole app|whole tag|\bsockets?\b|socket group|all sockets/i;
  const said = () =>
    [
      document.body.textContent ?? "",
      ...[...document.body.querySelectorAll("[title], [aria-label], [placeholder]")].flatMap((e) => ["title", "aria-label", "placeholder"].map((a) => e.getAttribute(a) ?? "")),
    ].join("\n");

  it("no Reserved screen says socket, Whole app or socket group", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<ReservedPage />);
    await inList().findByRole("button", { name: /^front/ });
    expect(said()).not.toMatch(banned);
    const panel = await openReservation(user, "front");
    expect(said()).not.toMatch(banned);
    await user.click(panel.getByRole("button", { name: "Add ports" }));
    await screen.findByRole("listbox", { name: "Ports of front" });
    expect(said()).not.toMatch(banned);
    await user.keyboard("{Escape}");
    await user.click(panel.getByRole("button", { name: "Release reservation" }));
    expect(said()).not.toMatch(banned);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "New reservation" }));
    expect(said()).not.toMatch(banned);
  });
});
