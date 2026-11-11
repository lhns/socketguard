import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { emit } from "@tauri-apps/api/event";
import App from "./App";
import type { AppDetail } from "./api";
import { detail, memoryStorage, mkApp, mockDaemon, renderWithProviders } from "./test/helpers";

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});

const nginx = mkApp("a1", "nginx", [80]);
const sshd = mkApp("a2", "sshd", [22]);
const settle = () => new Promise((r) => setTimeout(r, 100));
const inspector = () => screen.getByRole("region", { name: "Details" });

describe("requests", () => {
  it("every list is asked for once when the Apps page loads", async () => {
    const d = mockDaemon({ list_apps: () => [nginx, sshd] });
    renderWithProviders(<App />);
    await screen.findByText("nginx");
    await settle();
    for (const cmd of ["list_apps", "list_tags", "list_port_groups", "list_grants", "list_peers", "list_groups", "list_networks", "list_reservations", "status"]) {
      expect(d.count(cmd), cmd).toBe(1);
    }
    // No command twice, none of the selected-app ones before an app is selected.
    expect(d.calls.map((c) => c.cmd).filter((c, i, all) => all.indexOf(c) !== i)).toEqual([]);
    expect(d.count("get_app")).toBe(0);
  });

  it("selecting an app shows its name and ports at once, while the detail is still coming", async () => {
    let resolve!: (a: AppDetail) => void;
    const pending = new Promise<AppDetail>((r) => (resolve = r));
    const d = mockDaemon({ list_apps: () => [nginx, sshd], get_app: () => pending });
    renderWithProviders(<App />);
    await userEvent.click(await screen.findByText("nginx"));

    const panel = inspector();
    expect(await within(panel).findByRole("heading", { name: "nginx" })).toBeInTheDocument();
    expect(within(panel).getByText("80/tcp")).toBeInTheDocument();
    expect(within(panel).getAllByText("Loading…").length).toBeGreaterThan(0);
    expect(d.count("get_app")).toBe(1);

    resolve(detail(nginx));
    await waitFor(() => expect(within(panel).queryByText("Loading…")).not.toBeInTheDocument());
    expect(within(panel).getByText("Nobody can reach it.")).toBeInTheDocument();
  });

  it("an event that does not touch the app does not refetch its detail", async () => {
    const d = mockDaemon({ list_apps: () => [nginx, sshd], get_app: (a) => detail(a.id === "a1" ? nginx : sshd) });
    renderWithProviders(<App />);
    await userEvent.click(await screen.findByText("nginx"));
    await waitFor(() => expect(within(inspector()).queryByText("Loading…")).not.toBeInTheDocument());
    expect(d.count("get_app")).toBe(1);

    for (const ev of ["peers_changed", "activity", "tags_changed", "reservations_changed", "networks_changed", "settings_changed"]) await emit(ev);
    await settle();
    expect(d.count("get_app")).toBe(1);

    // A grant change does reach it.
    await emit("grants_changed");
    await waitFor(() => expect(d.count("get_app")).toBe(2));
  });
});
