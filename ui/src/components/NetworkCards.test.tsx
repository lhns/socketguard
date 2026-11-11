import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NetworksSection from "./NetworksSection";
import { mockDaemon, networkSetup, renderWithProviders, setupState } from "../test/helpers";
import type { NetworkSetup, SetupState } from "../api";

const withSetup = (over: Partial<NetworkSetup>): NetworkSetup => ({ ...networkSetup, ...over });
const card = async (name: string) => within(await screen.findByRole("article", { name }));
const network = (kind: string, name: string, iface: string | null = null) => ({
  id: name, name, kind, interface: iface, grants_apply: true, status: { state: "up" },
});

describe("Network cards", () => {
  it("shows a LAN card per interface not added yet, with its hints", async () => {
    mockDaemon({
      network_setup: () =>
        withSetup({ lan: [...networkSetup.lan, { interface: "eth0", has_ipv6_prefix: true, is_default_route: false, already_added: true }] }),
    });
    renderWithProviders(<NetworksSection />);
    const first = await card("LAN Ethernet 2");
    expect(first.getByText(/Red Hat VirtIO/)).toBeInTheDocument();
    expect(first.getByText("default route")).toBeInTheDocument();
    const second = await card("LAN Ethernet 3");
    expect(second.getAllByText(/no IPv6 prefix announced/).length).toBeGreaterThan(0);
    expect(screen.queryByRole("article", { name: "LAN eth0" })).not.toBeInTheDocument();
  });

  it("adds a LAN with the chosen interface, as DHCPv6 when toggled", async () => {
    const d = mockDaemon({ add_network: (a) => network("lan", "x", (a.req as { interface: string }).interface) });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    await user.click((await card("LAN Ethernet 2")).getByRole("button", { name: "Add Ethernet 2" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "slaac", interface: "Ethernet 2" });
    const third = await card("LAN Ethernet 3");
    await user.click(third.getByRole("checkbox", { name: "uses DHCPv6" }));
    await user.click(third.getByRole("button", { name: "Add Ethernet 3" }));
    await waitFor(() => expect(d.count("add_network")).toBe(2));
    expect(d.last("add_network")?.args.req).toEqual({ type: "dhcpv6", interface: "Ethernet 3" });
  });

  it("adds a ready Yggdrasil with no fields and shows what was found", async () => {
    const d = mockDaemon({
      network_setup: () =>
        withSetup({ yggdrasil: setupState("ready", { found: { address: "200:1::1", interface: "Yggdrasil", peers: "0" } }) }),
      add_network: () => network("yggdrasil", "yggdrasil", "Yggdrasil"),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    expect(await ygg.findByText(/200:1::1 on Yggdrasil/)).toBeInTheDocument();
    expect(ygg.getByText(/No peers yet/)).toBeInTheDocument();
    expect(ygg.getByText(/everything on the Yggdrasil adapter is blocked/)).toBeInTheDocument();
    await user.click(ygg.getByRole("button", { name: "Add Yggdrasil" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "yggdrasil" });
  });

  it("says how many peers a ready Yggdrasil has", async () => {
    mockDaemon({ network_setup: () => withSetup({ yggdrasil: setupState("ready", { found: { address: "200:1::1", interface: "Y", peers: "3" } }) }) });
    renderWithProviders(<NetworksSection />);
    expect(await (await card("Yggdrasil")).findByText("Connected to 3 peers.")).toBeInTheDocument();
  });

  it("offers Set up… for a stopped Yggdrasil and runs the elevated command", async () => {
    const stopped = setupState("not_running", { missing: "The Yggdrasil service is stopped." });
    const d = mockDaemon({
      network_setup: () => withSetup({ yggdrasil: stopped }),
      run_network_setup: () => ({ launched: true, cancelled: false, exit_code: 0, command: "" }),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    expect(ygg.queryByRole("button", { name: "Add Yggdrasil" })).not.toBeInTheDocument();
    await user.click(await ygg.findByRole("button", { name: "Set up…" }));
    expect(ygg.getByText("socketguard networks setup yggdrasil --yes")).toBeInTheDocument();
    expect(ygg.getByText("socketguard networks setup yggdrasil --undo")).toBeInTheDocument();
    expect(ygg.getByText(/setup-log.json/)).toBeInTheDocument();
    await user.click(ygg.getByRole("button", { name: "Run as administrator" }));
    await waitFor(() => expect(d.count("run_network_setup")).toBe(1));
    expect(d.last("run_network_setup")?.args).toEqual({ kind: "yggdrasil", config: networkSetup.config_path });
    // The state is asked again once it returned.
    await waitFor(() => expect(d.count("network_setup")).toBeGreaterThan(1));
  });

  it("explains what installing does on Windows and offers the winget command", async () => {
    mockDaemon({});
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    expect(await ygg.findByText("Yggdrasil is not installed. SocketGuard can install it with winget.")).toBeInTheDocument();
    await user.click(ygg.getByRole("button", { name: "Set up…" }));
    expect(ygg.getByText(/winget install --id YggdrasilNetwork.Yggdrasil/)).toBeInTheDocument();
    expect(ygg.getByText(/Installs the Yggdrasil service and its network adapter driver; it starts with Windows/)).toBeInTheDocument();
  });

  it("shows the command to run by hand when there is no elevation helper; a cancelled prompt is no error", async () => {
    let answer = { launched: false, cancelled: false, exit_code: null as number | null, command: "socketguard networks setup yggdrasil --yes --config C:/c.json" };
    mockDaemon({ run_network_setup: () => answer });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    await user.click(await ygg.findByRole("button", { name: "Set up…" }));
    await user.click(ygg.getByRole("button", { name: "Run as administrator" }));
    expect(await ygg.findByText(/--config C:\/c.json/)).toBeInTheDocument();
    answer = { ...answer, launched: true, cancelled: true };
    await user.click(ygg.getByRole("button", { name: "Run as administrator" }));
    expect(await ygg.findByText(/Cancelled: nothing was changed/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("Tor not installed without an offer gives the sentence, a download page and Check again", async () => {
    const d = mockDaemon({});
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const tor = await card("Tor");
    expect(await tor.findByText(/Windows has no package for it; download the Tor Expert Bundle, then come back here/)).toBeInTheDocument();
    expect(tor.queryByRole("button", { name: "Set up…" })).not.toBeInTheDocument();
    expect(tor.getByRole("button", { name: "Check again" })).toBeInTheDocument();
    await user.click(tor.getByRole("button", { name: "Download page" }));
    await waitFor(() => expect(d.count("open_download_page")).toBe(1));
    expect(d.last("open_download_page")?.args).toEqual({ url: "https://www.torproject.org/download/tor/" });
  });

  it("Tor that needs setup offers Set up… and a ready Tor adds with the default settings", async () => {
    const needs: SetupState = setupState("not_configured", { missing: "SocketGuard does not know Tor's cookie file yet." });
    mockDaemon({ network_setup: () => withSetup({ tor: needs, yggdrasil: setupState("added") }) });
    const { unmount } = renderWithProviders(<NetworksSection />);
    const tor = await card("Tor");
    expect(await tor.findByText("SocketGuard does not know Tor's cookie file yet.")).toBeInTheDocument();
    expect(tor.getByRole("button", { name: "Set up…" })).toBeInTheDocument();
    expect(screen.queryByRole("article", { name: "Yggdrasil" })).not.toBeInTheDocument();
    unmount();

    const d = mockDaemon({
      network_setup: () => withSetup({ tor: setupState("ready", { found: { control: "127.0.0.1:9051" } }) }),
      add_network: () => network("tor", "tor"),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    await user.click((await card("Tor")).getByRole("button", { name: "Add Tor" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "tor", control: "127.0.0.1:9051", auth: "cookie" });
  });

  it("Check again asks the daemon again", async () => {
    const d = mockDaemon({});
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    await screen.findByRole("article", { name: "Yggdrasil" });
    const before = d.count("network_setup");
    await user.click(screen.getAllByRole("button", { name: "Check again" })[0]);
    await waitFor(() => expect(d.count("network_setup")).toBeGreaterThan(before));
  });

  it("keeps the typed form under Advanced, with the interfaces to pick from", async () => {
    const d = mockDaemon({ add_network: () => network("lan", "dhcpv6-eth9", "eth9") });
    const user = userEvent.setup();
    const { container } = renderWithProviders(<NetworksSection />);
    await screen.findByRole("article", { name: "Yggdrasil" });
    const details = container.querySelector("details.advanced") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    await user.click(within(details).getByText("Advanced"));
    expect(container.querySelector("datalist option[value='Ethernet 2']")).not.toBeNull();
    await user.selectOptions(within(details).getByLabelText("Type"), "dhcpv6");
    await user.type(within(details).getByLabelText("Interface"), "eth9");
    await user.click(within(details).getByRole("button", { name: "Add network" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "dhcpv6", interface: "eth9" });
  });

  it("adds Local on the loopback interface the daemon named", async () => {
    const d = mockDaemon({
      network_setup: () => withSetup({ local: setupState("ready", { found: { interface: "lo0" } }) }),
      add_network: () => network("local", "ula", "lo0"),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    await user.click((await card("Local")).getByRole("button", { name: "Add Local" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "ula", interface: "lo0" });
  });

  it("does not offer anything for a kind that is already a network", async () => {
    mockDaemon({
      network_setup: () =>
        withSetup({ lan: [], yggdrasil: setupState("added"), tor: setupState("added"), local: setupState("added") }),
    });
    renderWithProviders(<NetworksSection />);
    expect(await screen.findByText(/Every network this machine offers is added/)).toBeInTheDocument();
  });
});
