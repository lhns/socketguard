import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { emit } from "@tauri-apps/api/event";
import PeersPage from "./pages/PeersPage";
import { useDaemonEvents } from "./queries";
import { alice, mockDaemon, renderWithProviders } from "./test/helpers";
import type { Peer } from "./api";

function Harness() {
  useDaemonEvents();
  return <PeersPage />;
}

describe("daemon events", () => {
  it("peers_changed refetches the peers list", async () => {
    let peers: Peer[] = [alice];
    const d = mockDaemon({ list_peers: () => peers });
    renderWithProviders(<Harness />);
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(d.count("list_peers")).toBe(1);

    peers = [alice, { ...alice, id: "p2", label: "carol" }];
    await emit("peers_changed");
    expect(await screen.findByText("carol")).toBeInTheDocument();
    await waitFor(() => expect(d.count("list_peers")).toBe(2));
  });

  it("an unrelated event does not refetch peers", async () => {
    const d = mockDaemon();
    renderWithProviders(<Harness />);
    await screen.findByText("alice");
    await emit("settings_changed");
    await new Promise((r) => setTimeout(r, 50));
    expect(d.count("list_peers")).toBe(1);
  });
});
