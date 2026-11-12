import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NetworksSection from "./NetworksSection";
import { kindSetup, mockDaemon, networkSetup, renderWithProviders, saved, setupState } from "../test/helpers";
import type { NetworkSetup } from "../api";

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
    const d = mockDaemon({ add_network: (a) => saved(network("lan", "x", (a.req as { interface: string }).interface)) });
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

  it("adds SocketGuard's own Yggdrasil and Tor with one click and says nothing is installed", async () => {
    const d = mockDaemon({ add_network: () => saved(network("yggdrasil", "yggdrasil", "ygg0")) });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    expect(ygg.getByText("SocketGuard runs its own Yggdrasil node. Nothing is installed or changed on your system.")).toBeInTheDocument();
    expect(ygg.getByText("Version 0.5.12")).toBeInTheDocument();
    expect(ygg.queryByRole("button", { name: /existing|my own/ })).not.toBeInTheDocument();
    await user.click(ygg.getByRole("button", { name: "Add Yggdrasil" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "yggdrasil", peers: [] });

    const tor = await card("Tor");
    expect(tor.getByText("SocketGuard runs its own Tor. Nothing is installed or changed on your system.")).toBeInTheDocument();
    await user.click(tor.getByRole("button", { name: "Add Tor" }));
    await waitFor(() => expect(d.count("add_network")).toBe(2));
    expect(d.last("add_network")?.args.req).toEqual({ type: "tor", bridges: [] });
  });

  it("an unavailable build says so and has no Add", async () => {
    mockDaemon({
      network_setup: () =>
        withSetup({
          yggdrasil: kindSetup({ available: false, reason: "the Yggdrasil files are missing" }),
          tor: kindSetup({ available: false, reason: "no Tor for this system" }),
        }),
    });
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    expect(ygg.getByText(/Not included in this build: the Yggdrasil files are missing/)).toBeInTheDocument();
    expect(ygg.queryByRole("button")).not.toBeInTheDocument();
    const tor = await card("Tor");
    expect(tor.getByText(/Not included in this build/)).toBeInTheDocument();
    expect(tor.queryByRole("button", { name: "Add Tor" })).not.toBeInTheDocument();
  });

  it("says plainly that another Yggdrasil node runs here, and Add stays available", async () => {
    const reason = "Another Yggdrasil node is running on this computer. SocketGuard's Yggdrasil cannot run next to it.";
    const d = mockDaemon({
      network_setup: () => withSetup({ yggdrasil: kindSetup({ reason }) }),
      add_network: () => saved(network("yggdrasil", "yggdrasil", "ygg0")),
    });
    const user = userEvent.setup();
    renderWithProviders(<NetworksSection />);
    const ygg = await card("Yggdrasil");
    const text = await ygg.findByText(reason);
    const add = ygg.getByRole("button", { name: "Add Yggdrasil" });
    expect(text.compareDocumentPosition(add) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryAllByText(reason)).toHaveLength(1);
    await user.click(add);
    await waitFor(() => expect(d.count("add_network")).toBe(1));
  });

  it("shows no card for a kind that is already added", async () => {
    mockDaemon({ network_setup: () => withSetup({ yggdrasil: kindSetup({ added: true }) }) });
    renderWithProviders(<NetworksSection />);
    await card("Tor");
    expect(screen.queryByRole("article", { name: "Yggdrasil" })).not.toBeInTheDocument();
  });

  it("has no setup flow any more", async () => {
    mockDaemon({});
    renderWithProviders(<NetworksSection />);
    await card("Tor");
    expect(screen.queryByRole("button", { name: /Set up|Download page|administrator/ })).not.toBeInTheDocument();
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
    const d = mockDaemon({ add_network: () => saved(network("lan", "dhcpv6-eth9", "eth9")) });
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
      add_network: () => saved(network("local", "ula", "lo0")),
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
        withSetup({ lan: [], yggdrasil: kindSetup({ added: true }), tor: kindSetup({ added: true }), local: setupState("added") }),
    });
    renderWithProviders(<NetworksSection />);
    expect(await screen.findByText(/Every network this machine offers is added/)).toBeInTheDocument();
  });
});
