import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import type { ChangesRequest } from "./api";
import { mockDaemon, renderWithProviders, saved } from "./test/helpers";

/** A working Storage: some Node versions shadow jsdom's with a broken experimental one. */
function memoryStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
  };
}
let storage = memoryStorage();
beforeEach(() => {
  storage = memoryStorage();
  vi.stubGlobal("localStorage", storage);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Simple / Advanced", () => {
  it("opens on the apps list, and Advanced switches to the access matrix and is remembered", async () => {
    mockDaemon();
    const user = userEvent.setup();
    const first = renderWithProviders(<App />);
    expect(await screen.findByRole("searchbox", { name: "Filter apps" })).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Access matrix" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Simple" })).toHaveAttribute("aria-pressed", "true");

    await user.click(screen.getByRole("button", { name: "Advanced" }));
    expect(await screen.findByRole("table", { name: "Access matrix" })).toBeInTheDocument();
    expect(storage.getItem("socketguard.mode")).toBe("advanced");
    first.unmount();

    // A new session starts where the last one ended.
    renderWithProviders(<App />);
    expect(await screen.findByRole("table", { name: "Access matrix" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Advanced" })).toHaveAttribute("aria-pressed", "true");
  });

  it("switching back to Simple returns to the apps list", async () => {
    storage.setItem("socketguard.mode", "advanced");
    mockDaemon();
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await screen.findByRole("table", { name: "Access matrix" });
    await user.click(screen.getByRole("button", { name: "Simple" }));
    expect(await screen.findByRole("searchbox", { name: "Filter apps" })).toBeInTheDocument();
    expect(storage.getItem("socketguard.mode")).toBe("simple");
  });

  it("works without usable storage", async () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    });
    mockDaemon();
    const user = userEvent.setup();
    renderWithProviders(<App />);
    expect(await screen.findByRole("searchbox", { name: "Filter apps" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Advanced" }));
    expect(await screen.findByRole("table", { name: "Access matrix" })).toBeInTheDocument();
  });

  it("has the five pages", async () => {
    mockDaemon();
    renderWithProviders(<App />);
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect([...nav.querySelectorAll("button")].map((b) => b.textContent?.replace(/\d+$/, ""))).toEqual([
      "Apps", "Access", "Peers & groups", "Activity", "Settings",
    ]);
  });
});

describe("pending enforcement (HTTP 202)", () => {
  it("shows the daemon's notice after a change that is saved but not yet enforced, until dismissed", async () => {
    const message = "saved, but not yet enforced; retrying (network 'tor': cannot reach the Tor control port)";
    const d = mockDaemon({
      changes: (a) =>
        saved({ dry_run: (a.req as ChangesRequest).dry_run, refs: {}, changes: [] }, { status: "pending", message }),
    });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await user.click(await screen.findByRole("button", { name: "Peers & groups" }));
    const box = await screen.findByLabelText("Keys, addresses or IPs");
    await user.click(box);
    await user.paste("10.0.0.1");
    await user.type(screen.getByLabelText("Label"), "bob");
    expect(screen.queryByText(/not enforced everywhere yet/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(d.count("changes")).toBe(1));
    const notice = await screen.findByRole("status");
    expect(notice).toHaveTextContent("Saved, but not enforced everywhere yet.");
    expect(notice).toHaveTextContent("cannot reach the Tor control port");
    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(/not enforced everywhere yet/)).not.toBeInTheDocument();
  });

  it("shows it for a plain delete too", async () => {
    mockDaemon({
      delete_peer: () => saved(null, { status: "pending", message: "tor is down" }),
    });
    const user = userEvent.setup();
    renderWithProviders(<App />);
    await user.click(await screen.findByRole("button", { name: "Peers & groups" }));
    await user.click(await screen.findByRole("button", { name: "Delete peer alice" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete peer" }));
    expect(await screen.findByText(/tor is down/)).toBeInTheDocument();
  });
});
