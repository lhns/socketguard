import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import PortableClose from "./components/PortableClose";
import SettingsPage from "./pages/SettingsPage";
import { memoryStorage, mockDaemon, renderWithProviders, status } from "./test/helpers";

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const unreachable = () => {
  throw { code: "connection", message: "Cannot reach the daemon", details: { hint: "Start it." } };
};
const portable = { portable_info: () => ({ portable: true }) };
const run = (exit_code = 0) => ({ launched: true, cancelled: false, exit_code, command: "socketguard-daemon --portable" });

describe("portable mode, daemon not started", () => {
  it("shows one state with a Start button that starts the portable daemon", async () => {
    const d = mockDaemon({ ...portable, status: unreachable, start_portable_daemon: () => run() });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("SocketGuard runs from this folder and is not started.");
    expect(alert).toHaveTextContent("It stops and removes its rules when you close this window.");
    expect(alert).toHaveTextContent("socketguard-daemon --portable");
    expect(within(alert).queryByText(/install/i)).not.toBeInTheDocument();
    await user.click(within(alert).getByRole("button", { name: "Start" }));
    await waitFor(() => expect(d.count("start_portable_daemon")).toBe(1));
    expect(d.count("service_status")).toBe(0);
    expect(d.count("current_account")).toBe(0);
  });

  it("shows the service_installed conflict as the command's message", async () => {
    mockDaemon({
      ...portable,
      status: unreachable,
      start_portable_daemon: () => {
        throw { code: "service_installed", message: "The SocketGuard service is installed; remove it first." };
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await user.click(await screen.findByRole("button", { name: "Start" }));
    expect(await screen.findByText("The SocketGuard service is installed; remove it first.")).toBeInTheDocument();
  });

  it("not portable: still the service states", async () => {
    const d = mockDaemon({ status: unreachable, service_status: () => ({ installed: false, running: false }) });
    renderWithProviders(<App />);
    const alert = await screen.findByRole("alert");
    expect(await within(alert).findByText(/service is not installed/)).toBeInTheDocument();
    expect(alert).not.toHaveTextContent("runs from this folder");
    expect(d.count("start_portable_daemon")).toBe(0);
  });
});

describe("the portable badge", () => {
  it("shows in portable mode, also while the daemon is unreachable", async () => {
    mockDaemon({ ...portable, status: unreachable });
    renderWithProviders(<App />);
    const badge = await screen.findByText("portable");
    expect(badge).toHaveAttribute("title", "Portable: protection ends when you close SocketGuard.");
  });

  it("is absent otherwise", async () => {
    mockDaemon();
    renderWithProviders(<App />);
    await screen.findByRole("button", { name: "Settings" });
    await waitFor(() => expect(screen.queryByText("portable")).not.toBeInTheDocument());
  });
});

describe("Settings", () => {
  it("portable: says to delete the folder, has no Remove button, shows the warnings", async () => {
    mockDaemon({ ...portable, status: () => ({ ...status, portable: true, db_protected: false, drop_events: false }) });
    renderWithProviders(<SettingsPage />);
    expect(await screen.findByText("Portable: delete this folder to remove SocketGuard. Your settings are in the data folder.")).toBeInTheDocument();
    expect(screen.getByText("Portable: protection ends when you close SocketGuard.")).toBeInTheDocument();
    expect(screen.getByText("The database is not protected: this drive has no access control.")).toBeInTheDocument();
    expect(screen.getByText(/Blocked connections are not logged/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Remove SocketGuard/ })).not.toBeInTheDocument();
  });

  it("not portable: keeps the Remove button and shows no portable text", async () => {
    mockDaemon();
    renderWithProviders(<SettingsPage />);
    expect(await screen.findByRole("button", { name: "Remove SocketGuard…" })).toBeInTheDocument();
    expect(screen.queryByText(/Portable:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/not protected/)).not.toBeInTheDocument();
  });
});

describe("closing the window in portable mode", () => {
  type CloseCb = (e: { preventDefault: () => void }) => void | Promise<void>;

  function setup(over: Parameters<typeof mockDaemon>[0] = {}, limitMs = 2000) {
    let alive = true;
    let cb: CloseCb = () => {};
    const d = mockDaemon({
      status: () => {
        if (alive) return status;
        return unreachable();
      },
      shutdown: () => {
        setTimeout(() => (alive = false), 30);
        return undefined;
      },
      portable_last_exit: () => ({ at: Date.now() / 1000, left: [] }),
      quit_app: () => undefined,
      ...over,
    });
    const subscribe = (c: CloseCb) => {
      cb = c;
      return Promise.resolve(() => {});
    };
    renderWithProviders(<PortableClose subscribe={subscribe} pollMs={10} limitMs={limitMs} />);
    const preventDefault = vi.fn();
    const close = () => act(() => void cb({ preventDefault }));
    return { d, close, preventDefault };
  }

  it("removes the rules, then quits when everything is gone", async () => {
    const { d, close, preventDefault } = setup();
    await close();
    expect(preventDefault).toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent("Removing rules…");
    await waitFor(() => expect(d.count("quit_app")).toBe(1));
    expect(d.count("shutdown")).toBe(1);
    expect(d.calls.findIndex((c) => c.cmd === "shutdown")).toBeLessThan(d.calls.findIndex((c) => c.cmd === "quit_app"));
  });

  it("an old exit record does not count", async () => {
    const { d, close } = setup({ portable_last_exit: () => ({ at: Date.now() / 1000 - 3600, left: ["old rule"] }) });
    await close();
    await waitFor(() => expect(d.count("quit_app")).toBe(1));
  });

  it("lists what could not be removed and quits only on Close anyway", async () => {
    const { d, close } = setup({ portable_last_exit: () => ({ at: Date.now() / 1000, left: ["firewall rule 12", "address fd00::1"] }) });
    const user = userEvent.setup();
    await close();
    expect(await screen.findByText("Some things could not be removed:")).toBeInTheDocument();
    expect(screen.getByText("firewall rule 12")).toBeInTheDocument();
    expect(screen.getByText("address fd00::1")).toBeInTheDocument();
    expect(d.count("quit_app")).toBe(0);
    await user.click(screen.getByRole("button", { name: "Close anyway" }));
    await waitFor(() => expect(d.count("quit_app")).toBe(1));
  });

  it("carries on when shutdown fails because the daemon is already gone", async () => {
    const { d, close } = setup({ shutdown: unreachable, status: unreachable });
    await close();
    await waitFor(() => expect(d.count("quit_app")).toBe(1));
  });

  it("times out when the daemon keeps answering", async () => {
    const { d, close } = setup({ shutdown: () => undefined }, 100);
    const user = userEvent.setup();
    await close();
    expect(await screen.findByText("SocketGuard did not stop in time. Its rules are removed when the process ends.")).toBeInTheDocument();
    expect(d.count("quit_app")).toBe(0);
    expect(d.count("portable_last_exit")).toBe(0);
    await user.click(screen.getByRole("button", { name: "Close anyway" }));
    await waitFor(() => expect(d.count("quit_app")).toBe(1));
  });
});
