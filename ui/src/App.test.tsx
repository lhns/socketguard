import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import type { ChangesRequest } from "./api";
import {
  detail, grantView, memoryStorage, mkApp, mkGroup, mkPeer, mkTag, mockDaemon, renderWithProviders, saved,
} from "./test/helpers";

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const nginx = mkApp("a1", "nginx", [80]);
const sshd = mkApp("a2", "sshd", [22]);
const alice = mkPeer("p1", "alice", { groups: ["g1"] });
const team = mkGroup("g1", "team", ["p1"]);
const web = mkTag("t1", "web", ["a1"]);
const gTeam = grantView({ id: "g-team", target: { kind: "tag", id: "t1" }, subject: { kind: "group", id: "g1" } });

function setup(over: Parameters<typeof mockDaemon>[0] = {}) {
  return mockDaemon({
    list_apps: () => [nginx, sshd],
    get_app: (a) => detail(a.id === "a1" ? nginx : sshd, a.id === "a1" ? { access: [{ grant_id: "g-team", port: null, network_id: null, subject: gTeam.subject, origin: { kind: "tag", tag_id: "t1" } }], grants: [], tags: ["t1"] } : {}),
    list_peers: () => [alice],
    list_groups: () => [team],
    list_tags: () => [web],
    list_grants: () => [gTeam],
    ...over,
  });
}

const navButtons = () =>
  [...within(screen.getByRole("navigation", { name: "Main" })).getAllByRole("button")].map((b) => b.textContent?.replace(/\d+$/, ""));

describe("navigation", () => {
  it("is Apps, Peers, Activity and Settings: no Access tab, no Simple/Advanced switch", async () => {
    setup();
    renderWithProviders(<App />);
    await screen.findByRole("table", { name: "Apps and tags" });
    expect(navButtons()).toEqual(["Apps", "Peers", "Activity", "Settings"]);
    expect(screen.queryByRole("button", { name: "Simple" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Advanced" })).not.toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "View" })).not.toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Access matrix" })).not.toBeInTheDocument();
  });

  it("opens on Apps", async () => {
    setup();
    renderWithProviders(<App />);
    expect(await screen.findByRole("searchbox", { name: "Filter apps" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Apps/ })).toHaveAttribute("aria-current", "page");
  });

  it("does not remount pages: selection and filters survive switching tabs and following a link", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<App />);
    const apps = await screen.findByRole("table", { name: "Apps and tags" });
    await user.type(screen.getByRole("searchbox", { name: "Filter apps" }), "n");
    await user.click(within(apps).getByRole("checkbox", { name: "Select nginx" }));
    const panel = await screen.findByRole("region", { name: "Details" });
    await within(panel).findByRole("heading", { name: "nginx" });

    // Off to Peers and back: the same page, not a fresh one.
    await user.click(screen.getByRole("button", { name: "Peers" }));
    await screen.findByRole("table", { name: "Peers and groups" });
    expect(screen.queryByRole("table", { name: "Apps and tags" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Apps/ }));
    expect(screen.getByRole("searchbox", { name: "Filter apps" })).toHaveValue("n");
    expect(within(screen.getByRole("table", { name: "Apps and tags" })).getByRole("checkbox", { name: "Select nginx" })).toBeChecked();
    expect(d.count("list_apps")).toBe(1);

    // A link inside Apps (the tag the app's access comes through) selects the tag and keeps the filter.
    await user.click(await within(await screen.findByRole("region", { name: "Details" })).findByRole("button", { name: "Go to tag web" }));
    expect(await screen.findByRole("heading", { name: "web" })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Filter apps" })).toHaveValue("n");
  });

  it("a link to a peer's group opens Peers on it, and the Apps selection is still there afterwards", async () => {
    setup({
      get_app: () => detail(nginx, { access: [], grants: [], tags: [] }),
    });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    const apps = await screen.findByRole("table", { name: "Apps and tags" });
    await user.click(await within(apps).findByRole("checkbox", { name: "Select sshd" }));
    await user.click(screen.getByRole("button", { name: "Peers" }));
    const peers = await screen.findByRole("table", { name: "Peers and groups" });
    await user.click(await within(peers).findByRole("checkbox", { name: "Select alice" }));
    const p = await screen.findByRole("region", { name: "Peer details" });
    await user.click(await within(p).findByRole("button", { name: "Go to group team" }));
    expect(await within(await screen.findByRole("region", { name: "Peer details" })).findByRole("heading", { name: "team" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Apps/ }));
    expect(within(screen.getByRole("table", { name: "Apps and tags" })).getByRole("checkbox", { name: "Select sshd" })).toBeChecked();
  });

  it("the chosen overview columns survive going to Peers and back", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await screen.findByRole("table", { name: "Apps and tags" });
    await user.click(screen.getByRole("button", { name: /^Columns/ }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    expect(within(screen.getByRole("table", { name: "Apps and tags" })).getByRole("columnheader", { name: "alice" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Peers" }));
    await user.click(screen.getByRole("button", { name: /^Apps/ }));
    expect(within(screen.getByRole("table", { name: "Apps and tags" })).getByRole("columnheader", { name: "alice" })).toBeInTheDocument();
  });

  it("a peer's Show as column adds it to Apps and goes there", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await screen.findByRole("table", { name: "Apps and tags" });
    await user.click(screen.getByRole("button", { name: "Peers" }));
    const peers = await screen.findByRole("table", { name: "Peers and groups" });
    await user.click(within(peers).getByRole("checkbox", { name: "Select alice" }));
    await user.click(await within(await screen.findByRole("region", { name: "Peer details" })).findByRole("button", { name: "Show as column in Apps" }));
    expect(screen.getByRole("button", { name: /^Apps/ })).toHaveAttribute("aria-current", "page");
    expect(within(screen.getByRole("table", { name: "Apps and tags" })).getByRole("columnheader", { name: "alice" })).toBeInTheDocument();
  });
});

describe("pending enforcement (HTTP 202)", () => {
  it("shows the daemon's notice after a change that is saved but not yet enforced, until dismissed", async () => {
    const message = "saved, but not yet enforced; retrying (network 'tor': cannot reach the Tor control port)";
    const d = setup({
      changes: (a) =>
        saved({ dry_run: (a.req as ChangesRequest).dry_run, refs: {}, changes: [], changes_reach: false }, { status: "pending", message }),
    });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await user.click(await screen.findByRole("button", { name: "Peers" }));
    await user.click(await screen.findByRole("button", { name: "Add peers" }));
    const box = await screen.findByLabelText("Keys, addresses or IPs");
    await user.click(box);
    await user.paste("10.0.0.1");
    expect(screen.queryByText(/not enforced everywhere yet/)).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Create 1 peer" }));
    await waitFor(() => expect(d.count("changes")).toBe(2));
    const notice = await screen.findByRole("status");
    expect(notice).toHaveTextContent("Saved, but not enforced everywhere yet.");
    expect(notice).toHaveTextContent("cannot reach the Tor control port");
    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(/not enforced everywhere yet/)).not.toBeInTheDocument();
  });

  it("shows it for a plain delete too", async () => {
    setup({ delete_peer: () => saved(null, { status: "pending", message: "tor is down" }) });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await user.click(await screen.findByRole("button", { name: "Peers" }));
    const peers = await screen.findByRole("table", { name: "Peers and groups" });
    await user.click(within(peers).getByRole("checkbox", { name: "Select alice" }));
    await user.click(await within(await screen.findByRole("region", { name: "Peer details" })).findByRole("button", { name: "Delete peer alice" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete peer" }));
    expect(await screen.findByText(/tor is down/)).toBeInTheDocument();
  });
});
