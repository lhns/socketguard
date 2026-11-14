import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import PeersPage from "./PeersPage";
import type { ChangesRequest, GrantView } from "../api";
import {
  batch, grantView, memoryStorage, mkApp, mkGroup, mkPeer, mkReservation, mkTag, mockDaemon, networks, renderWithProviders, saved,
} from "../test/helpers";

const KEY = "b".repeat(64);
const alice = mkPeer("p1", "alice", { groups: ["g1"] });
const bob = mkPeer("p2", "bob");
const carol = mkPeer("p3", "carol", { credentials: [] });
const team = mkGroup("g1", "team", ["p1"]);
const ops = mkGroup("g2", "ops", []);
const nginx = mkApp("a1", "nginx", [80]);
const web = mkTag("t1", "web", ["a1"]);

const gAlice = grantView({ id: "g-alice", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p1" } });
const gTeam = grantView({ id: "g-team", target: { kind: "tag", id: "t1" }, subject: { kind: "group", id: "g1" } });
const gAnyone = grantView({ id: "g-any", target: { kind: "app", id: "a1" }, subject: { kind: "anyone" }, reach: [{ network_id: "n-ygg", reach: "open" }] });
const gLan = grantView({ id: "g-lan", target: { kind: "tag", id: "t1" }, subject: { kind: "anyone" }, network_id: "n-lan", reach: [{ network_id: "n-lan", reach: "open" }] });

const applied = (d: ReturnType<typeof mockDaemon>) =>
  d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest).filter((r) => !r.dry_run).map((r) => r.ops);

function setup(over: Parameters<typeof mockDaemon>[0] = {}, grants: GrantView[] = [gAlice, gTeam, gAnyone, gLan]) {
  return mockDaemon({
    list_apps: () => [nginx],
    list_tags: () => [web],
    list_peers: () => [alice, bob, carol],
    list_groups: () => [team, ops],
    list_grants: () => grants,
    list_networks: () => networks,
    changes: (a) => batch(a.req as ChangesRequest),
    ...over,
  });
}

const list = () => screen.getByRole("table", { name: "Peers and groups" });
const inList = () => within(list());
const panel = () => screen.getByRole("region", { name: "Peer details" });
const rowButton = async (name: string) => {
  const box = await inList().findByRole("checkbox", { name: `Select ${name}` });
  return within(box.closest("tr")!).getByRole("button", { name });
};

let storage = memoryStorage();
beforeEach(() => {
  storage = memoryStorage();
  vi.stubGlobal("localStorage", storage);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Peers list", () => {
  it("has Built-in, Groups and Peers as sections of one table; built-in rows have no checkbox", async () => {
    setup();
    renderWithProviders(<PeersPage />);
    await rowButton("alice");
    expect(inList().getByText("Built-in")).toBeInTheDocument();
    expect(inList().getByText(/^Groups \(2\)/)).toBeInTheDocument();
    expect(inList().getByText(/^Peers \(3\)/)).toBeInTheDocument();
    expect(inList().getByRole("button", { name: "Anyone" })).toBeInTheDocument();
    expect(inList().getByRole("button", { name: "Everyone on LAN" })).toBeInTheDocument();
    expect(inList().queryByRole("checkbox", { name: "Select Anyone" })).not.toBeInTheDocument();
    expect(inList().getByRole("checkbox", { name: "Select team" })).toBeInTheDocument();
  });

  it("searches, filters by a group pill, and selects a range", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await rowButton("alice");
    await user.type(screen.getByRole("searchbox", { name: "Filter peers" }), "bo");
    expect(inList().queryByRole("button", { name: "alice" })).not.toBeInTheDocument();
    expect(inList().getByRole("button", { name: "bob" })).toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox", { name: "Filter peers" }));

    await user.click(inList().getAllByRole("button", { name: "team" }).find((b) => b.classList.contains("tag-pill"))!);
    expect(inList().queryByRole("button", { name: "bob" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Stop filtering by group team/ }));

    await user.click(inList().getByRole("checkbox", { name: "Select alice" }));
    await user.keyboard("{Shift>}");
    await user.click(inList().getByRole("checkbox", { name: "Select carol" }));
    await user.keyboard("{/Shift}");
    expect(inList().getByRole("checkbox", { name: "Select bob" })).toBeChecked();
    expect(await screen.findByRole("heading", { name: "3 peers selected" })).toBeInTheDocument();
  });
});

describe("Inspector: built-in rows", () => {
  it("Anyone is not editable and lists what is open to everyone", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await inList().findByRole("button", { name: "Anyone" }));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    expect(p.getByRole("heading", { name: "Anyone" })).toBeInTheDocument();
    expect(p.getByRole("button", { name: "nginx" })).toBeInTheDocument();
    expect(p.queryByRole("button", { name: /Revoke/ })).not.toBeInTheDocument();
    expect(p.queryByRole("button", { name: /Add access/ })).not.toBeInTheDocument();
    expect(p.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("Everyone on LAN lists what is open to that network", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await inList().findByRole("button", { name: "Everyone on LAN" }));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    expect(p.getByRole("heading", { name: "Everyone on LAN" })).toBeInTheDocument();
    expect(p.getByText("tag web")).toBeInTheDocument();
    expect(p.queryByText("nginx")).not.toBeInTheDocument();
  });
});

describe("Inspector: one peer", () => {
  it("shows credentials with badges, groups, and what it can reach with where each access comes from", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("alice"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    expect(await p.findByRole("heading", { name: "alice" })).toBeInTheDocument();
    expect(p.getByText("Yggdrasil key")).toBeInTheDocument();
    expect(p.getByText("verified")).toBeInTheDocument();
    expect(p.getByRole("button", { name: "team" })).toBeInTheDocument();
    const what = p.getByRole("heading", { name: "What it can reach" }).closest("section")!;
    expect(within(what).getByRole("button", { name: "Revoke nginx" })).toBeInTheDocument();
    // The grant of its group is changed at the group.
    expect(within(what).getByRole("button", { name: "Go to group team" })).toBeInTheDocument();
    expect(within(what).getAllByRole("button", { name: /^Revoke/ })).toHaveLength(1);
  });

  it("the peer-side form says what is missing while What is empty", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    await user.click(await p.findByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    expect(within(form).getByText("Choose what it can reach")).toBeInTheDocument();
    await user.click(within(form).getByRole("combobox", { name: "What" }));
    await user.click(screen.getByRole("checkbox", { name: "nginx" }));
    await user.keyboard("{Escape}");
    expect(within(form).queryByText("Choose what it can reach")).not.toBeInTheDocument();
  });

  it("add access from the peer side: the peer is fixed, an app or tag is picked", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    await user.click(await p.findByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    expect(form).toHaveTextContent("What can bob reach?");
    await user.click(within(form).getByRole("combobox", { name: "What" }));
    await user.click(screen.getByRole("checkbox", { name: /^web/ }));
    await user.click(screen.getByRole("checkbox", { name: "nginx" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "All ports" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "add_grant", target: { kind: "tag", id: "t1" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p2" }, confirm_open: false },
      { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p2" }, confirm_open: false },
    ]);
  });

  it("joining a group that has grants shows who gains access first; leaving applies at once with Undo", async () => {
    const d = setup({ set_group_members: () => saved(team) });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    await user.click(await p.findByRole("button", { name: "Add or remove groups" }));
    await user.click(screen.getByRole("checkbox", { name: /^team/ }));
    const review = await screen.findByRole("dialog");
    expect(review).toHaveTextContent("bob in group team");
    expect(review).toHaveTextContent("gains access to tag web");
    expect(d.count("set_group_members")).toBe(0);
    await user.click(within(review).getByRole("button", { name: "Add to group" }));
    await waitFor(() => expect(d.last("set_group_members")?.args).toEqual({ id: "g1", peerIds: ["p1", "p2"] }));
  });

  it("joining a group without grants applies at once", async () => {
    const d = setup({ set_group_members: () => saved(ops) });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    await user.click(await p.findByRole("button", { name: "Add or remove groups" }));
    await user.click(screen.getByRole("checkbox", { name: /^ops/ }));
    await waitFor(() => expect(d.last("set_group_members")?.args).toEqual({ id: "g2", peerIds: ["p2"] }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("a group can be created from the picker, with the peer in it", async () => {
    const d = setup({ create_group: (a) => ({ id: "g9", label: (a.req as { label: string }).label, members: [], created_at: "" }) });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    await user.click(await p.findByRole("button", { name: "Add or remove groups" }));
    await user.type(screen.getByRole("combobox", { name: "Search Groups" }), "staging{Enter}");
    await waitFor(() => expect(d.last("create_group")?.args.req).toEqual({ label: "staging", members: ["p2"] }));
  });

  it("Show as column in Apps remembers the column and goes to Apps", async () => {
    setup();
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />, go);
    await user.click(await rowButton("alice"));
    await user.click(await within(panel()).findByRole("button", { name: "Show as column in Apps" }));
    expect(JSON.parse(storage.getItem("socketguard.columns")!)).toEqual(["peer:p1"]);
    expect(go).toHaveBeenCalledWith("apps");
  });

  it("generates a Tor access key and shows the private key once", async () => {
    const d = setup({
      generate_tor_key: () => saved({ credential: { id: "c9", kind: "tor_client_key", value: "ABC", label: null }, private_key: "PRIVATEKEY123" }),
    });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("alice"));
    await user.click(await within(panel()).findByRole("button", { name: "Generate Tor access key" }));
    const dialog = await screen.findByRole("dialog", { name: "Tor access key for alice" });
    expect(within(dialog).getByTestId("tor-private-key")).toHaveTextContent("PRIVATEKEY123");
    expect(d.last("generate_tor_key")?.args).toEqual({ peerId: "p1" });
    await user.click(within(dialog).getByRole("button", { name: "I have copied it" }));
    expect(screen.queryByTestId("tor-private-key")).not.toBeInTheDocument();
  });

  it("deleting a peer asks first", async () => {
    const d = setup({ delete_peer: () => saved(null) });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    await user.click(await within(panel()).findByRole("button", { name: "Delete peer bob" }));
    expect(d.count("delete_peer")).toBe(0);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete peer" }));
    await waitFor(() => expect(d.last("delete_peer")?.args).toEqual({ id: "p2" }));
  });
});

describe("Inspector: a group", () => {
  it("members are picked, what it can reach is listed, and it can be shown as a column", async () => {
    const d = setup({ set_group_members: () => saved(team) });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("team"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    expect(await p.findByRole("heading", { name: "team" })).toBeInTheDocument();
    expect(p.getByRole("button", { name: "alice" })).toBeInTheDocument();
    expect(p.getByRole("button", { name: "Revoke tag web" })).toBeInTheDocument();
    expect(p.getByRole("button", { name: "Show as column in Apps" })).toBeInTheDocument();
    // Removing the only member closes: at once.
    await user.click(p.getByRole("button", { name: "Add or remove members" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await waitFor(() => expect(d.last("set_group_members")?.args).toEqual({ id: "g1", peerIds: [] }));
    expect(await screen.findByRole("button", { name: "Undo" })).toBeInTheDocument();
  });

  it("a new group is made from the Groups header, deleting one asks first", async () => {
    const d = setup({
      create_group: () => ({ id: "g9", label: "lab", members: [], created_at: "" }),
      delete_group: () => saved(null),
    });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await inList().findByRole("button", { name: "New group" }));
    await user.type(await screen.findByLabelText("Group name"), "lab");
    await user.click(screen.getByRole("button", { name: "Create group" }));
    await waitFor(() => expect(d.last("create_group")?.args.req).toEqual({ label: "lab", members: [] }));

    await user.click(await rowButton("ops"));
    await user.click(await within(panel()).findByRole("button", { name: "Delete group ops" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete group" }));
    await waitFor(() => expect(d.last("delete_group")?.args).toEqual({ id: "g2" }));
  });
});

describe("Inspector: several groups", () => {
  it("lists what they can reach and deletes them after asking once", async () => {
    const toOps = grantView({ id: "g-ops", target: { kind: "app", id: "a1" }, subject: { kind: "group", id: "g2" } });
    const d = setup({ delete_group: () => saved(null) }, [gTeam, toOps]);
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select team" }));
    await user.click(inList().getByRole("checkbox", { name: "Select ops" }));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    expect(await p.findByRole("heading", { name: "2 groups selected" })).toBeInTheDocument();
    // Each is the access of one of the two groups.
    expect(p.getAllByText("1 of 2 groups")).toHaveLength(2);
    await user.click(p.getByRole("button", { name: "Delete 2 groups" }));
    expect(d.count("delete_group")).toBe(0);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete groups" }));
    await waitFor(() => expect(d.count("delete_group")).toBe(2));
  });
});

describe("Inspector: several peers", () => {
  async function selectAll(user: ReturnType<typeof userEvent.setup>) {
    for (const n of ["alice", "bob"]) await user.click(await inList().findByRole("checkbox", { name: `Select ${n}` }));
    return within(await screen.findByRole("region", { name: "Peer details" }));
  }

  it("shows the groups some have as mixed and what they can reach in common or in part", async () => {
    const d = setup({}, [gAlice, grantView({ id: "g-bob", target: { kind: "app", id: "a1" }, subject: { kind: "peer", id: "p2" } })]);
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    const p = await selectAll(user);
    expect(await p.findByRole("heading", { name: "2 peers selected" })).toBeInTheDocument();
    expect(p.getByRole("button", { name: "team 1/2" })).toBeInTheDocument();
    await user.click(p.getByRole("button", { name: "Add or remove groups" }));
    expect(((screen.getByRole("checkbox", { name: /^team/ })) as HTMLInputElement).indeterminate).toBe(true);
    await user.keyboard("{Escape}");
    // The same access of both is one entry covering both; Revoke removes both grants.
    const what = p.getByRole("heading", { name: "What they can reach" }).closest("section")!;
    expect(within(what).getByText("all 2 peers")).toBeInTheDocument();
    await user.click(within(what).getByRole("button", { name: "Revoke nginx" }));
    await waitFor(() => expect(applied(d)).toEqual([[{ op: "remove_grant", grant_id: "g-alice" }, { op: "remove_grant", grant_id: "g-bob" }]]));
  });

  it("adds access for all of them in one batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    const p = await selectAll(user);
    await user.click(await p.findByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("combobox", { name: "What" }));
    await user.click(screen.getByRole("checkbox", { name: "nginx" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "All ports" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].map((o) => (o as { subject: { id: string } }).subject.id)).toEqual(["p1", "p2"]);
  });

  it("deleting several asks once", async () => {
    const d = setup({ delete_peer: () => saved(null) });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    const p = await selectAll(user);
    await user.click(await p.findByRole("button", { name: "Delete 2 peers" }));
    expect(d.count("delete_peer")).toBe(0);
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete peers" }));
    await waitFor(() => expect(d.count("delete_peer")).toBe(2));
  });
});

// ─── Adding peers ───────────────────────────────────────────────────────────

async function openAdd(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await inList().findByRole("button", { name: "Add peers" }));
  return screen.findByLabelText("Keys, addresses or IPs");
}
async function paste(user: ReturnType<typeof userEvent.setup>, text: string) {
  // user.type would treat "{" and "[" specially; paste is what people do.
  const box = await openAdd(user);
  await user.click(box);
  await user.paste(text);
}

describe("Add peers", () => {
  it("is a button in the list header that opens the form in the inspector, with the explanation folded", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await openAdd(user);
    expect(screen.getByRole("region", { name: "Peer details" })).toContainElement(screen.getByLabelText("Keys, addresses or IPs"));
    const help = screen.getByText("Key, address or subnet? And Tor.").closest("details")!;
    expect(help).not.toHaveAttribute("open");
  });

  it("makes one peer per pasted value, sends no name and creates them in one batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, `10.0.0.1, fd00::1\n${KEY}`);
    const chips = await screen.findByRole("list", { name: "Parsed values" });
    await waitFor(() => expect(within(chips).getAllByRole("listitem")).toHaveLength(3));
    expect(within(chips).getAllByText("IP")).toHaveLength(2);
    expect(screen.queryByLabelText("Label")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /One peer per value/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Create 3 peers" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([
      { op: "create_peer", ref: "$new0", credentials: [{ kind: "ip", value: "10.0.0.1", label: null }] },
      { op: "create_peer", ref: "$new1", credentials: [{ kind: "ip", value: "fd00::1", label: null }] },
      { op: "create_peer", ref: "$new2", credentials: [{ kind: "ygg_key", value: KEY, label: null }] },
    ]);
  });

  it("adds one peer with a key", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, KEY);
    await user.click(await screen.findByRole("button", { name: "Create 1 peer" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toEqual([{ op: "create_peer", ref: "$new0", credentials: [{ kind: "ygg_key", value: KEY, label: null }] }]);
  });

  it("puts all the new peers into a new group in the same batch when Create group is ticked", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, "10.0.0.1 10.0.0.2");
    expect(screen.queryByLabelText("Group name")).not.toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Create group" })).not.toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: "Create group" }));
    await user.type(screen.getByLabelText("Group name"), "lab");
    await user.click(await screen.findByRole("button", { name: "Create 2 peers" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(d.count("create_group")).toBe(0);
    expect(applied(d)[0]).toEqual([
      { op: "create_peer", ref: "$new0", credentials: [{ kind: "ip", value: "10.0.0.1", label: null }] },
      { op: "create_peer", ref: "$new1", credentials: [{ kind: "ip", value: "10.0.0.2", label: null }] },
      { op: "create_group", ref: "$group", label: "lab", members: ["$new0", "$new1"] },
    ]);
  });

  it("has Cancel in the footer and no second way out in the header", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await openAdd(user);
    expect(screen.queryByRole("button", { name: "Close details" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Close" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByLabelText("Keys, addresses or IPs")).not.toBeInTheDocument();
  });

  it("shows the parser's error at the values and sends nothing", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, "not-an-ip");
    await user.click(screen.getByRole("button", { name: /^Create/ }));
    expect((await screen.findAllByRole("alert"))[0]).toHaveTextContent('cannot tell what "not-an-ip" is');
    expect(d.count("changes")).toBe(0);
  });

  it("puts a group name conflict at the group name", async () => {
    setup({ changes: () => { throw { code: "conflict", message: "operation 1: group lab already exists", details: null }; } });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, "10.0.0.1");
    await user.click(screen.getByRole("checkbox", { name: "Create group" }));
    await user.type(screen.getByLabelText("Group name"), "lab");
    await user.click(await screen.findByRole("button", { name: "Create 1 peer" }));
    const err = await screen.findByText("group lab already exists");
    expect(err.closest(".form-row")).toContainElement(screen.getByLabelText("Group name"));
  });
});

describe("Inspector close", () => {
  it("× hides the inspector and keeps the rows ticked; ticking a row shows it again", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await inList().findByRole("checkbox", { name: "Select alice" }));
    await user.click(inList().getByRole("checkbox", { name: "Select bob" }));
    const region = await screen.findByRole("region", { name: "Peer details" });
    await user.click(within(region).getByRole("button", { name: "Close details" }));
    expect(screen.queryByRole("region", { name: "Peer details" })).not.toBeInTheDocument();
    expect(inList().getByRole("checkbox", { name: "Select alice" })).toBeChecked();
    expect(inList().getByRole("checkbox", { name: "Select bob" })).toBeChecked();
    await user.click(inList().getByRole("checkbox", { name: "Select carol" }));
    expect(await screen.findByRole("heading", { name: "3 peers selected" })).toBeInTheDocument();
  });

  it("a peer has a + pill for its groups", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("alice"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    const plus = await p.findByRole("button", { name: "Add or remove groups" });
    expect(plus).toHaveClass("tag-pill", "tag-pill-add");
    expect(p.queryByRole("button", { name: "Groups…" })).not.toBeInTheDocument();
  });
});

describe("Reserved addresses as a target", () => {
  const front = mkReservation("r1", "front", [{ kind: "app", app_id: "a1", scope: { kind: "all" } }]);
  const gRes = grantView({ id: "g-res", target: { kind: "reservation", id: "r1" }, subject: { kind: "peer", id: "p1" } });

  it("what a peer can reach lists a reservation grant as `reserved <name>`", async () => {
    setup({ list_reservations: () => [front] }, [gRes]);
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("alice"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    const what = p.getByRole("heading", { name: "What it can reach" }).closest("section")!;
    expect(await within(what).findByRole("button", { name: "reserved front" })).toBeInTheDocument();
  });

  it("the target picker also lists reserved addresses, with only All ports to open", async () => {
    const d = setup({ list_reservations: () => [front] });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await rowButton("bob"));
    const p = within(await screen.findByRole("region", { name: "Peer details" }));
    await user.click(await p.findByRole("button", { name: "Add access…" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("combobox", { name: "What" }));
    const option = await screen.findByRole("checkbox", { name: /^reserved front/ });
    expect(option.closest("li")).toHaveTextContent("Reserved addresses");
    await user.click(option);
    await user.keyboard("{Escape}");
    expect([...within(form).getByRole("group", { name: "What to open" }).querySelectorAll("button")].map((b) => b.textContent)).toEqual(["All ports"]);
    await user.click(within(form).getByRole("button", { name: "All ports" }));
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toEqual([[
      { op: "add_grant", target: { kind: "reservation", id: "r1" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p2" }, confirm_open: false },
    ]]));
  });
});
