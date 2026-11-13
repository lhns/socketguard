import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import SettingsPage from "./SettingsPage";
import { memoryStorage, mockDaemon, networks, renderWithProviders, saved, settings, status } from "../test/helpers";

const risk = {
  process_name: "sshd",
  port: 22,
  protocol: "tcp",
  bind_address: "::",
  message: "sshd on :::22/tcp has no grant",
};

describe("Leaving a Tor or Yggdrasil network", () => {
  it("removing the network says its own node stops and asks nothing else", async () => {
    const withNode = { ...networks[1], child: { state: "up" as const, peers: [] } };
    const d = mockDaemon({ list_networks: () => [withNode], delete_network: () => undefined });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByRole("button", { name: "Remove network Yggdrasil" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/SocketGuard's Yggdrasil stops with it/)).toBeInTheDocument();
    expect(within(dialog).queryByText(/keeps running|reachable over it/)).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove network" }));
    await waitFor(() => expect(d.count("delete_network")).toBe(1));
    expect(d.last("delete_network")?.args).toEqual({ id: "n-ygg", force: false });
  });

  it("turning SocketGuard off asks for one confirmation and nothing about a node that keeps running", async () => {
    const d = mockDaemon({ disable: () => undefined });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByRole("button", { name: "Turn SocketGuard off" }));
    const dialog = await screen.findByRole("dialog", { name: "Turn SocketGuard off?" });
    expect(within(dialog).queryByText(/keeps running/)).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Turn SocketGuard off" }));
    await waitFor(() => expect(d.count("disable")).toBe(1));
  });
});

describe("Settings page", () => {
  it("shows the risks when protect-host is refused and can force", async () => {
    const d = mockDaemon({
      set_protect_host: (a) => {
        if (!(a.req as { force: boolean }).force) {
          throw { code: "protect_host_refused", message: "refused", details: [risk] };
        }
        return { settings: { ...settings, protect_host_interfaces: ["eth0"] }, overridden: [risk] };
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByRole("checkbox", { name: "eth0" }));
    await user.click(screen.getByRole("button", { name: "Apply" }));
    const dialog = await screen.findByRole("dialog", { name: "This would cut off remote access" });
    expect(within(dialog).getByText(/sshd on :::22\/tcp has no grant/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Enable anyway" }));
    await waitFor(() => expect(d.count("set_protect_host")).toBe(2));
    expect(d.last("set_protect_host")?.args.req).toEqual({ interfaces: ["eth0"], force: true });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("links a risk to its app", async () => {
    mockDaemon({
      set_protect_host: () => {
        throw { code: "protect_host_refused", message: "refused", details: [risk] };
      },
    });
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />, go);
    await user.click(await screen.findByRole("checkbox", { name: "eth0" }));
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await user.click(await screen.findByRole("button", { name: /Grant them first/ }));
    expect(go).toHaveBeenCalledWith("apps", { search: "sshd" });
  });

  it("adds a LAN network for a VLAN interface", async () => {
    const d = mockDaemon({ add_network: () => saved({ ...status.networks[2], id: "slaac-eth0.20", name: "slaac-eth0.20" }) });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    const form = await screen.findByRole("form", { name: "Add a network" });
    await user.type(within(form).getByLabelText("Interface"), "eth0.20");
    await user.click(within(form).getByRole("button", { name: "Add network" }));
    await waitFor(() => expect(d.count("add_network")).toBe(1));
    expect(d.last("add_network")?.args.req).toEqual({ type: "slaac", interface: "eth0.20" });
  });

  it("puts an interface error at the interface field", async () => {
    mockDaemon({
      add_network: () => {
        throw { code: "invalid", message: "interface 'nope' does not exist", details: null };
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    const form = await screen.findByRole("form", { name: "Add a network" });
    await user.type(within(form).getByLabelText("Interface"), "nope");
    await user.click(within(form).getByRole("button", { name: "Add network" }));
    const err = await within(form).findByText(/does not exist/);
    expect(err.closest(".form-row")).toContainElement(within(form).getByLabelText("Interface"));
  });

  it("removes a network after confirming", async () => {
    const d = mockDaemon({ delete_network: () => undefined });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByRole("button", { name: "Remove network LAN" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove network" }));
    await waitFor(() => expect(d.count("delete_network")).toBe(1));
    expect(d.last("delete_network")?.args).toEqual({ id: "n-lan", force: false });
  });

  it("previews an import as a diff before applying it", async () => {
    const d = mockDaemon({
      apply_state: (a) => ({
        dry_run: (a.req as { dry_run: boolean }).dry_run,
        changes: [{ kind: "create", item: "peer", name: "carol", detail: "1 credentials", opens_to_anyone: false }],
        confirm_open_required: false,
      }),
    });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByLabelText("Import a document"));
    await user.paste('{"version":1}');
    await user.click(screen.getByRole("button", { name: "Preview changes" }));
    expect(await screen.findByText("carol")).toBeInTheDocument();
    expect((d.last("apply_state")?.args.req as { dry_run: boolean }).dry_run).toBe(true);
    await user.click(screen.getByRole("button", { name: "Apply 1 changes" }));
    await waitFor(() => expect(d.count("apply_state")).toBe(2));
    expect((d.last("apply_state")?.args.req as { dry_run: boolean }).dry_run).toBe(false);
    expect((d.last("apply_state")?.args.req as { confirm_open: boolean }).confirm_open).toBe(false);
  });

  it("asks before an import that affects what Anyone can reach, then confirms it", async () => {
    const d = mockDaemon({
      apply_state: (a) => ({
        dry_run: (a.req as { dry_run: boolean }).dry_run,
        changes: [{ kind: "create", item: "grant", name: "nginx to Anyone", opens_to_anyone: true }],
        confirm_open_required: true,
      }),
    });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByLabelText("Import a document"));
    await user.paste('{"version":1}');
    await user.click(screen.getByRole("button", { name: "Preview changes" }));
    await user.click(await screen.findByRole("button", { name: "Apply 1 changes" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Some of these changes affect what Anyone can reach. Apply them?");
    expect(d.count("apply_state")).toBe(1);
    await user.click(within(dialog).getByRole("button", { name: "Apply anyway" }));
    await waitFor(() => expect(d.count("apply_state")).toBe(2));
    expect(d.last("apply_state")?.args.req).toMatchObject({ dry_run: false, confirm_open: true });
  });

  it("turns SocketGuard off with its effect spelled out", async () => {
    const d = mockDaemon({ disable: () => undefined });
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage />);
    await user.click(await screen.findByRole("button", { name: "Turn SocketGuard off" }));
    const dialog = await screen.findByRole("dialog", { name: "Turn SocketGuard off?" });
    expect(dialog).toHaveTextContent(/removes all firewall rules and addresses/);
    expect(dialog).toHaveTextContent(/as open as the network allows/);
    await user.click(within(dialog).getByRole("button", { name: "Turn SocketGuard off" }));
    await waitFor(() => expect(d.count("disable")).toBe(1));
  });

  it("words the unadopted state in plain terms", async () => {
    mockDaemon({ status: () => ({ ...status, unadopted: true }), enable: () => undefined });
    renderWithProviders(<SettingsPage />);
    expect(await screen.findByText(/Rules from an earlier install are active, but this database doesn't know them/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Adopt them and turn on" })).toBeInTheDocument();
  });

  describe("Remove SocketGuard", () => {
    const ok = { launched: true, cancelled: false, exit_code: 0, command: "x" };
    const open = async (user: ReturnType<typeof userEvent.setup>) => {
      await user.click(await screen.findByRole("button", { name: "Remove SocketGuard…" }));
      return screen.findByRole("dialog", { name: "Remove SocketGuard?" });
    };

    it("explains what goes, keeps settings by default, runs the uninstall with --keep-data, then clears the window and closes", async () => {
      vi.stubGlobal("localStorage", memoryStorage());
      localStorage.setItem("socketguard.columns", '["p1"]');
      const d = mockDaemon({ remove_socketguard: () => ok, clear_local_ui_settings: () => undefined, quit_app: () => undefined });
      const user = userEvent.setup();
      renderWithProviders(<SettingsPage />);
      const dialog = await open(user);
      expect(dialog).toHaveTextContent(/firewall rules/);
      expect(dialog).toHaveTextContent(/service/);
      expect(dialog).toHaveTextContent(/access group, if SocketGuard created it/);
      expect(dialog).toHaveTextContent(/own Tor and Yggdrasil/);
      expect(within(dialog).getByRole("checkbox", { name: "Also delete settings and keys?" })).not.toBeChecked();
      expect(dialog).toHaveTextContent("socketguard-daemon uninstall --yes --keep-data");
      expect(dialog).toHaveTextContent("Onion addresses cannot be recovered.");
      await user.click(within(dialog).getByRole("button", { name: "Remove SocketGuard" }));
      await waitFor(() => expect(d.count("quit_app")).toBe(1));
      expect(d.last("remove_socketguard")?.args).toEqual({ purge: false });
      expect(localStorage.getItem("socketguard.columns")).toBeNull();
      vi.unstubAllGlobals();
      expect(d.calls.map((c) => c.cmd).filter((c) => ["remove_socketguard", "clear_local_ui_settings", "quit_app"].includes(c))).toEqual([
        "remove_socketguard", "clear_local_ui_settings", "quit_app",
      ]);
    });

    it("deleting settings and keys runs the uninstall with --purge", async () => {
      const d = mockDaemon({ remove_socketguard: () => ok, clear_local_ui_settings: () => undefined, quit_app: () => undefined });
      const user = userEvent.setup();
      renderWithProviders(<SettingsPage />);
      const dialog = await open(user);
      await user.click(within(dialog).getByRole("checkbox", { name: "Also delete settings and keys?" }));
      expect(dialog).toHaveTextContent("socketguard-daemon uninstall --yes --purge");
      await user.click(within(dialog).getByRole("button", { name: "Remove SocketGuard" }));
      await waitFor(() => expect(d.count("quit_app")).toBe(1));
      expect(d.last("remove_socketguard")?.args).toEqual({ purge: true });
    });

    it("Export first saves the export and removes nothing", async () => {
      vi.stubGlobal("URL", { ...URL, createObjectURL: () => "blob:x", revokeObjectURL: () => {} });
      const d = mockDaemon({ export_state: () => ({ version: 1 }) });
      const user = userEvent.setup();
      renderWithProviders(<SettingsPage />);
      const dialog = await open(user);
      await user.click(within(dialog).getByRole("button", { name: "Export first" }));
      await waitFor(() => expect(d.count("export_state")).toBe(1));
      expect(await within(dialog).findByText(/Saved socketguard-export.json/)).toBeInTheDocument();
      expect(d.count("remove_socketguard")).toBe(0);
      vi.unstubAllGlobals();
    });

    it("a failed uninstall keeps the window open and does not clear its settings", async () => {
      const d = mockDaemon({ remove_socketguard: () => ({ ...ok, exit_code: 1 }), clear_local_ui_settings: () => undefined, quit_app: () => undefined });
      const user = userEvent.setup();
      renderWithProviders(<SettingsPage />);
      const dialog = await open(user);
      await user.click(within(dialog).getByRole("button", { name: "Remove SocketGuard" }));
      expect(await within(dialog).findByText(/exit code 1/)).toBeInTheDocument();
      expect(d.count("clear_local_ui_settings")).toBe(0);
      expect(d.count("quit_app")).toBe(0);
    });
  });
});
