import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NetworksSection from "./NetworksSection";
import { bridgeError, childStateText, peerError } from "./NetworkChild";
import { ALLOWED_LINKS } from "../links";
import { mockDaemon, renderWithProviders, saved } from "../test/helpers";
import type { ChildInfo, Network } from "../api";

const ygg = (child?: ChildInfo): Network => ({
  id: "n-ygg", kind: "yggdrasil", name: "Yggdrasil", interface: "ygg0", grants_apply: true, status: { state: "up" }, child,
});
const row = async (name: string) => within((await screen.findByRole("button", { name: `Remove network ${name}` })).closest("li") as HTMLElement);

describe("child state in words", () => {
  const t = (m: Partial<ChildInfo>) => childStateText({ state: "up", lan_discovery: false, ...m });
  it("says each state plainly", () => {
    expect(t({ state: "starting" })).toBe("Starting");
    expect(t({ state: "bootstrapping", lan_discovery: false, progress: 40 })).toBe("Bootstrapping 40%");
    expect(t({ state: "up", lan_discovery: false })).toBe("Up");
    expect(t({ state: "exited", detail: "bind failed" })).toBe("Exited: bind failed");
    expect(t({ state: "waiting", lan_discovery: false, detail: "another Yggdrasil node is running on this host" })).toBe("another Yggdrasil node is running on this host");
    expect(t({ state: "stopped" })).toBe("Stopped (SocketGuard is turned off)");
    expect(t({ state: "unavailable" })).toBe("Not included in this build");
  });
});

describe("peer URIs", () => {
  it("accepts scheme, host and port, rejects the rest", () => {
    for (const ok of ["tls://ygg.example.org:443", "tcp://1.2.3.4:1", "quic://[2001:db8::1]:65535", "socks://127.0.0.1:9050/ygg.example.org:443"]) {
      expect(peerError(ok)).toBeNull();
    }
    for (const bad of ["ygg.example.org:443", "http://a.org:80", "tls://a.org", "tls://a.org:0", "tls://a.org:70000", "tls://:443", "tls://[::1]"]) {
      expect(peerError(bad)).not.toBeNull();
    }
  });
});

describe("Configured networks", () => {
  it("show the child's state", async () => {
    mockDaemon({
      list_networks: () => [
        ygg({ state: "up", lan_discovery: false, runs_as: "socketguard-net", version: "0.5.12", peers: [] }),
        { id: "n-tor", kind: "tor", name: "Tor", interface: null, grants_apply: true, status: { state: "up" }, child: { state: "bootstrapping", lan_discovery: false, progress: 62, peers: [] } },
      ],
    });
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.queryByText("managed")).not.toBeInTheDocument();
    expect(y.getByText("Up")).toBeInTheDocument();
    expect(y.getByText("runs as socketguard-net")).toBeInTheDocument();
    expect((await row("Tor")).getByText("Bootstrapping 62%")).toBeInTheDocument();
  });

  it("shows no node details for a network without a child state", async () => {
    mockDaemon({ list_networks: () => [ygg()] });
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.queryByText("your own")).not.toBeInTheDocument();
    expect(y.queryByRole("group", { name: "Peers" })).not.toBeInTheDocument();
  });

  it("explains a waiting node with the daemon's sentence", async () => {
    const detail = "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it.";
    mockDaemon({ list_networks: () => [ygg({ state: "waiting", lan_discovery: false, detail, peers: [] })] });
    renderWithProviders(<NetworksSection />);
    expect((await row("Yggdrasil")).getByText(detail)).toBeInTheDocument();
  });

  it("show the address with Copy and the peer count, or say there are no peers", async () => {
    mockDaemon({ list_networks: () => [ygg({ state: "up", lan_discovery: false, address: "200:1::1", peers: ["tls://a.org:443"], peers_connected: 2 })] });
    const user = userEvent.setup();
    const { unmount } = renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.getByText("200:1::1")).toBeInTheDocument();
    expect(y.getByText("Connected to 2 peers.")).toBeInTheDocument();
    await user.click(y.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("200:1::1");
    unmount();

    mockDaemon({ list_networks: () => [ygg({ state: "up", lan_discovery: false, address: "200:1::1", peers: [], peers_connected: 0 })] });
    renderWithProviders(<NetworksSection />);
    expect((await row("Yggdrasil")).getByText("No peers yet, and finding nodes on the local network is off: it has nobody to talk to. Add a peer below or turn on local network discovery.")).toBeInTheDocument();
  });

  it("in portable mode, say that a killed SocketGuard leaves the Wintun driver", async () => {
    const note = /Wintun\) installed if SocketGuard is closed unexpectedly; it is removed on a normal exit/;
    mockDaemon({ portable_info: () => ({ portable: true }), list_networks: () => [ygg({ state: "up", lan_discovery: false, address: "200:1::1", peers: [] })] });
    const { unmount } = renderWithProviders(<NetworksSection />);
    expect(await (await row("Yggdrasil")).findByText(note)).toBeInTheDocument();
    unmount();

    mockDaemon({ list_networks: () => [ygg({ state: "up", lan_discovery: false, address: "200:1::1", peers: [] })] });
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.getByText("200:1::1")).toBeInTheDocument();
    expect(y.queryByText(note)).not.toBeInTheDocument();
  });

  it("edit the peers: add, reject an invalid URI, remove, save", async () => {
    const d = mockDaemon({
      list_networks: () => [ygg({ state: "up", lan_discovery: false, peers: ["tls://a.org:443"], peers_connected: 1 })],
      set_network_peers: () => saved(ygg()),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    const save = y.getByRole("button", { name: "Save peers" });
    expect(save).toBeDisabled();
    expect(y.getByText("Saving restarts SocketGuard's node.")).toBeInTheDocument();

    await user.type(y.getByLabelText("New peer"), "http://b.org:80");
    await user.click(y.getByRole("button", { name: "Add peer" }));
    expect(y.getByRole("alert")).toHaveTextContent(/scheme must be one of/);
    expect(save).toBeDisabled();

    await user.clear(y.getByLabelText("New peer"));
    await user.type(y.getByLabelText("New peer"), "tcp://b.org:1234");
    await user.click(y.getByRole("button", { name: "Add peer" }));
    expect(y.getByText("tcp://b.org:1234")).toBeInTheDocument();
    await user.click(y.getByRole("button", { name: "Remove peer tls://a.org:443" }));
    expect(y.queryByText("tls://a.org:443")).not.toBeInTheDocument();
    await user.click(save);
    await waitFor(() => expect(d.count("set_network_peers")).toBe(1));
    expect(d.last("set_network_peers")?.args).toEqual({ id: "n-ygg", peers: ["tcp://b.org:1234"] });
  });

  it("LAN discovery is off, says what it means, and turning it on asks first", async () => {
    const d = mockDaemon({
      list_networks: () => [ygg({ state: "up", lan_discovery: false, peers: [] })],
      set_network_lan_discovery: () => ygg(),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    const sw = y.getByRole("switch", { name: "Find Yggdrasil nodes on the local network" });
    expect(sw).not.toBeChecked();
    expect(y.getByText(/Other computers on your local network can connect to this computer's Yggdrasil node\. They cannot reach your apps unless you grant access\./)).toBeInTheDocument();
    await user.click(sw);
    // Nothing is sent until the dialog is confirmed.
    expect(d.count("set_network_lan_discovery")).toBe(0);
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(d.count("set_network_lan_discovery")).toBe(1));
    expect(d.last("set_network_lan_discovery")?.args).toEqual({ id: "n-ygg", enabled: true, confirmOpen: true });
  });

  it("turning LAN discovery off needs no question", async () => {
    const d = mockDaemon({
      list_networks: () => [ygg({ state: "up", lan_discovery: true, peers: [] })],
      set_network_lan_discovery: () => ygg(),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    await user.click(y.getByRole("switch", { name: "Find Yggdrasil nodes on the local network" }));
    await waitFor(() => expect(d.count("set_network_lan_discovery")).toBe(1));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(d.last("set_network_lan_discovery")?.args).toEqual({ id: "n-ygg", enabled: false, confirmOpen: false });
  });
});

const FP = "0123456789ABCDEF0123456789ABCDEF01234567";
const CERT = "A".repeat(70);
const bridge = (host: number, port = 443) => `obfs4 192.0.2.${host}:${port} ${FP} cert=${CERT} iat-mode=0`;
const tor = (child?: ChildInfo): Network => ({
  id: "n-tor", kind: "tor", name: "Tor", interface: null, grants_apply: true, status: { state: "up" }, child,
});

describe("bridge lines", () => {
  it("accept only obfs4 lines of the supported form", () => {
    for (const ok of [bridge(1), `Bridge ${bridge(2)}`, `obfs4 [2001:db8::1]:9001 ${FP.toLowerCase()} cert=${CERT} iat-mode=2`]) {
      expect(bridgeError(ok)).toBeNull();
    }
    for (const bad of [
      "", "obfs4", `${bridge(1)} SocksPort 1`, `${bridge(1)}\nSocksPort 1`, `${bridge(1)}\u{2028}x`, `${bridge(1)}\0`, `${bridge(1)}#`,
      `"${bridge(1)}"`, `snowflake 192.0.2.3:80 ${FP}`, `meek_lite 192.0.2.20:80 url=https://x.example/`,
      `webtunnel [2001:db8::1]:443 ${FP} url=https://x.example/y`, bridge(1, 0), bridge(1, 65536), bridge(1).replace("192.0.2.1", "192.0.2.256"),
      bridge(1).replace("192.0.2.1", "bridge.example.org"), bridge(1).replace(FP, FP.slice(1)), bridge(1).replace(CERT, CERT.slice(1)),
      bridge(1).replace("iat-mode=0", "iat-mode=3"), "x".repeat(5000),
    ]) {
      expect(bridgeError(bad), JSON.stringify(bad.slice(0, 40))).not.toBeNull();
    }
  });
});

describe("Bridges of Tor", () => {
  it("are off by default, with the help and the link", async () => {
    const d = mockDaemon({ list_networks: () => [tor({ state: "up", lan_discovery: false, peers: [] })], open_link: () => undefined });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const t = await row("Tor");
    expect(t.getByText("Bridges (if Tor is blocked on this network)")).toBeInTheDocument();
    expect(t.getByLabelText("Bridge lines")).toHaveValue("");
    expect(t.getByRole("button", { name: "Save bridges" })).toBeDisabled();
    await user.click(t.getByRole("link", { name: "Get bridges from the Tor Project" }));
    await waitFor(() => expect(d.count("open_link")).toBe(1));
    expect(d.last("open_link")?.args).toEqual({ url: "https://bridges.torproject.org/" });
  });

  it("show an error per line and save only valid lines, one per line", async () => {
    const d = mockDaemon({ list_networks: () => [tor({ state: "up", lan_discovery: false, peers: [] })], set_network_bridges: () => tor() });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const t = await row("Tor");
    const box = t.getByLabelText("Bridge lines");
    await user.click(box);
    await user.paste(`${bridge(1)}\nsnowflake 192.0.2.3:80 ${FP}\r\n\n${bridge(2)} SocksPort 1`);
    const save = t.getByRole("button", { name: "Save bridges" });
    expect(save).toBeDisabled();
    const errors = t.getAllByRole("alert").map((e) => e.textContent ?? "");
    expect(errors).toHaveLength(2);
    expect(errors[0]).toMatch(/^Line 2: Only obfs4 bridges are supported/);
    expect(errors[1]).toMatch(/^Line 3:/);

    await user.clear(box);
    await user.click(box);
    await user.paste(`${bridge(1)}\n\n  ${bridge(2)}  \n`);
    expect(t.queryAllByRole("alert")).toHaveLength(0);
    expect(save).toBeEnabled();
    await user.click(save);
    await waitFor(() => expect(d.count("set_network_bridges")).toBe(1));
    expect(d.last("set_network_bridges")?.args).toEqual({ id: "n-tor", bridges: [bridge(1), bridge(2)] });
  });

  it("show the saved bridges, and emptying them turns bridges off", async () => {
    const d = mockDaemon({ list_networks: () => [tor({ state: "bootstrapping", lan_discovery: false, progress: 10, peers: [], bridges: [bridge(1)] })], set_network_bridges: () => tor() });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const t = await row("Tor");
    expect(t.getByLabelText("Bridge lines")).toHaveValue(bridge(1));
    expect(t.getByText("Bootstrapping 10% through bridges")).toBeInTheDocument();
    await user.clear(t.getByLabelText("Bridge lines"));
    await user.click(t.getByRole("button", { name: "Save bridges" }));
    await waitFor(() => expect(d.count("set_network_bridges")).toBe(1));
    expect(d.last("set_network_bridges")?.args).toEqual({ id: "n-tor", bridges: [] });
  });

  it("cannot be set in a build without the helper, and the card says why", async () => {
    const why = "bridges are not available: this build does not include the obfs4 helper (lyrebird)";
    mockDaemon({ list_networks: () => [tor({ state: "up", lan_discovery: false, peers: [], bridges_unavailable: why })] });
    renderWithProviders(<NetworksSection />);
    const t = await row("Tor");
    expect(t.getByText(why)).toBeInTheDocument();
    expect(t.getByLabelText("Bridge lines")).toBeDisabled();
    expect(t.getByRole("button", { name: "Save bridges" })).toBeDisabled();
  });

  it("that are already saved can still be removed when the build has no helper", async () => {
    const why = "bridges are not available: this build does not include the obfs4 helper (lyrebird)";
    const d = mockDaemon({
      list_networks: () => [tor({ state: "up", lan_discovery: false, peers: [], bridges: [bridge(1)], bridges_unavailable: why })],
      set_network_bridges: () => tor(),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const t = await row("Tor");
    const save = t.getByRole("button", { name: "Save bridges" });
    expect(save).toBeDisabled();
    await user.clear(t.getByLabelText("Bridge lines"));
    await user.click(save);
    await waitFor(() => expect(d.count("set_network_bridges")).toBe(1));
    expect(d.last("set_network_bridges")?.args).toEqual({ id: "n-tor", bridges: [] });
  });

  it("show the daemon's refusal", async () => {
    mockDaemon({
      list_networks: () => [tor({ state: "up", lan_discovery: false, peers: [] })],
      set_network_bridges: () => { throw { code: "invalid", message: "invalid bridge: nope" }; },
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const t = await row("Tor");
    await user.click(t.getByLabelText("Bridge lines"));
    await user.paste(bridge(1));
    await user.click(t.getByRole("button", { name: "Save bridges" }));
    expect(await t.findByText("invalid bridge: nope")).toBeInTheDocument();
  });

  it("are not offered for a Tor network without a child state", async () => {
    mockDaemon({ list_networks: () => [tor()] });
    renderWithProviders(<NetworksSection />);
    await row("Tor");
    expect(screen.queryByLabelText("Bridge lines")).not.toBeInTheDocument();
  });
});

describe("Public Yggdrasil peers", () => {
  it("are one link away, with a sentence of help", async () => {
    const d = mockDaemon({ list_networks: () => [ygg({ state: "up", lan_discovery: false, peers: [] })], open_link: () => undefined });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.getByText(/A new node reaches nobody until you add peers or turn on discovery on the local network\./)).toBeInTheDocument();
    await user.click(y.getByRole("link", { name: "Find public peers" }));
    await waitFor(() => expect(d.count("open_link")).toBe(1));
    expect(d.last("open_link")?.args).toEqual({ url: "https://github.com/yggdrasil-network/public-peers" });
  });

  it("the links the window opens are the allow-listed ones", () => {
    expect(ALLOWED_LINKS).toEqual(["https://bridges.torproject.org/", "https://github.com/yggdrasil-network/public-peers"]);
  });
});

describe("Wording", () => {
  it("the networks screen avoids the retired words", async () => {
    mockDaemon({ list_networks: () => [ygg({ state: "waiting", lan_discovery: false, detail: "waiting", peers: [] })] });
    renderWithProviders(<NetworksSection />);
    await screen.findByRole("article", { name: "Tor" });
    expect(document.body.textContent ?? "").not.toMatch(/whole app|whole tag|\bsockets?\b|socket group/i);
  });
});
