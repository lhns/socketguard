import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NetworksSection from "./NetworksSection";
import { childStateText, peerError } from "./ManagedNetwork";
import { mockDaemon, renderWithProviders, saved } from "../test/helpers";
import type { ManagedInfo, Network } from "../api";

const ygg = (managed?: ManagedInfo): Network => ({
  id: "n-ygg", kind: "yggdrasil", name: "Yggdrasil", interface: "ygg0", grants_apply: true, status: { state: "up" }, managed,
});
const row = async (name: string) => within((await screen.findByRole("button", { name: `Remove network ${name}` })).closest("li") as HTMLElement);

describe("child state in words", () => {
  const t = (m: Partial<ManagedInfo>) => childStateText({ state: "up", ...m });
  it("says each state plainly", () => {
    expect(t({ state: "starting" })).toBe("Starting");
    expect(t({ state: "bootstrapping", progress: 40 })).toBe("Bootstrapping 40%");
    expect(t({ state: "up" })).toBe("Up");
    expect(t({ state: "exited", detail: "bind failed" })).toBe("Exited: bind failed");
    expect(t({ state: "waiting", detail: "another Yggdrasil node is running on this host" })).toBe("another Yggdrasil node is running on this host");
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
  it("tell managed from your own, and the child's state", async () => {
    mockDaemon({
      list_networks: () => [
        ygg({ state: "up", runs_as: "socketguard-net", version: "0.5.12", peers: [] }),
        { id: "n-tor", kind: "tor", name: "Tor", interface: null, grants_apply: true, status: { state: "up" }, managed: { state: "bootstrapping", progress: 62, peers: [] } },
      ],
    });
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.getByText("managed")).toBeInTheDocument();
    expect(y.getByText("Up")).toBeInTheDocument();
    expect(y.getByText("runs as socketguard-net")).toBeInTheDocument();
    expect((await row("Tor")).getByText("Bootstrapping 62%")).toBeInTheDocument();
  });

  it("shows an unmanaged node as your own, with no managed details", async () => {
    mockDaemon({ list_networks: () => [ygg()] });
    renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.getByText("your own")).toBeInTheDocument();
    expect(y.queryByRole("group", { name: "Peers" })).not.toBeInTheDocument();
  });

  it("explains a waiting node with the daemon's sentence", async () => {
    const detail = "another Yggdrasil node is running on this host; SocketGuard's own node cannot run next to it yet";
    mockDaemon({ list_networks: () => [ygg({ state: "waiting", detail, peers: [] })] });
    renderWithProviders(<NetworksSection />);
    expect((await row("Yggdrasil")).getByText(detail)).toBeInTheDocument();
  });

  it("show the address with Copy and the peer count, or say there are no peers", async () => {
    mockDaemon({ list_networks: () => [ygg({ state: "up", address: "200:1::1", peers: ["tls://a.org:443"], peers_connected: 2 })] });
    const user = userEvent.setup();
    const { unmount } = renderWithProviders(<NetworksSection />);
    const y = await row("Yggdrasil");
    expect(y.getByText("200:1::1")).toBeInTheDocument();
    expect(y.getByText("Connected to 2 peers.")).toBeInTheDocument();
    await user.click(y.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe("200:1::1");
    unmount();

    mockDaemon({ list_networks: () => [ygg({ state: "up", address: "200:1::1", peers: [], peers_connected: 0 })] });
    renderWithProviders(<NetworksSection />);
    expect((await row("Yggdrasil")).getByText("No peers yet: it only finds nodes on your LAN.")).toBeInTheDocument();
  });

  it("edit the peers: add, reject an invalid URI, remove, save", async () => {
    const d = mockDaemon({
      list_networks: () => [ygg({ state: "up", peers: ["tls://a.org:443"], peers_connected: 1 })],
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
});

describe("Wording", () => {
  it("the networks screen avoids the retired words", async () => {
    mockDaemon({ list_networks: () => [ygg({ state: "waiting", detail: "waiting", peers: [] })] });
    renderWithProviders(<NetworksSection />);
    await screen.findByRole("article", { name: "Tor" });
    expect(document.body.textContent ?? "").not.toMatch(/whole app|whole tag|\bsockets?\b|socket group/i);
  });
});
