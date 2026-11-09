import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import SettingsPage from "./SettingsPage";
import { mockDaemon, renderWithProviders, settings } from "../test/helpers";

const risk = {
  process_name: "sshd",
  port: 22,
  protocol: "tcp",
  bind_address: "::",
  message: "sshd on :::22/tcp has no grant",
};

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
    renderWithProviders(<SettingsPage onShowApp={vi.fn()} />);
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
    const onShowApp = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<SettingsPage onShowApp={onShowApp} />);
    await user.click(await screen.findByRole("checkbox", { name: "eth0" }));
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await user.click(await screen.findByRole("button", { name: /Grant them first/ }));
    expect(onShowApp).toHaveBeenCalledWith("sshd");
  });

  it("lists networks and mentions the CLI for adding", async () => {
    mockDaemon();
    renderWithProviders(<SettingsPage onShowApp={() => {}} />);
    expect(await screen.findByText("Yggdrasil")).toBeInTheDocument();
    expect(screen.getByText("socketguard networks add")).toBeInTheDocument();
  });
});
