import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ActivityPage from "./ActivityPage";
import { mockDaemon, renderWithProviders, status } from "../test/helpers";
import type { ActivityRecord } from "../api";

const rec = (over: Partial<ActivityRecord>): ActivityRecord => ({
  id: 1,
  at: "2026-01-01T00:00:00Z",
  kind: "app_discovered",
  app_id: "a1",
  peer_id: null,
  network_id: null,
  src: null,
  port: null,
  proto: null,
  count: 1,
  message: "nginx is listening",
  ...over,
});

describe("Activity page", () => {
  it("is a log: no quick actions, and a row opens its app", async () => {
    mockDaemon({ activity: () => [rec({})] });
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />, go);
    expect(await screen.findByText("nginx is listening")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Keep closed" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Grant/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Open nginx/ }));
    expect(go).toHaveBeenCalledWith("apps", { appId: "a1" });
  });

  it("opens a peer from a row about a peer", async () => {
    mockDaemon({ activity: () => [rec({ kind: "peer_added", app_id: null, peer_id: "p1", message: "added alice" })] });
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />, go);
    await user.click(await screen.findByRole("button", { name: /Open alice/ }));
    expect(go).toHaveBeenCalledWith("peers", { peerId: "p1" });
  });

  it("filters by source and shows the aggregated counts", async () => {
    mockDaemon({
      activity: () => [
        rec({ id: 3, kind: "blocked", src: "192.0.2.9", count: 12, message: "blocked 192.0.2.9" }),
        rec({ id: 2, kind: "blocked", src: "198.51.100.1", count: 3, message: "blocked 198.51.100.1" }),
      ],
    });
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />);
    expect(await screen.findByTestId("activity-summary")).toHaveTextContent("2 entries, 15 events");
    await user.type(screen.getByLabelText("Source"), "192.0.2");
    expect(screen.getByTestId("activity-summary")).toHaveTextContent("1 entry, 12 events");
    expect(screen.queryByText("blocked 198.51.100.1")).not.toBeInTheDocument();
  });

  it("filters by peer on the server", async () => {
    const d = mockDaemon({ activity: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />);
    await screen.findByRole("option", { name: "alice" });
    await user.selectOptions(screen.getByLabelText("Peer"), "alice");
    await waitFor(() => expect((d.last("activity")?.args.query as { peer_id: string }).peer_id).toBe("p1"));
  });

  it("has no banner about new apps", async () => {
    mockDaemon({ activity: () => [] });
    renderWithProviders(<ActivityPage />);
    await screen.findByRole("option", { name: "alice" });
    expect(screen.queryByText(/need a decision|needs a decision/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Review in Apps" })).not.toBeInTheDocument();
  });

  it("offers Load more when a page is full and passes the cursor", async () => {
    const page = Array.from({ length: 50 }, (_, i) =>
      rec({ id: 100 - i, kind: "peer_added", app_id: null, message: `m${100 - i}` }),
    );
    const d = mockDaemon({
      activity: (a) => ((a.query as { before: number | null }).before === null ? page : []),
    });
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />);
    await user.click(await screen.findByRole("button", { name: "Load more" }));
    await waitFor(() => expect(d.count("activity")).toBe(2));
    expect((d.last("activity")?.args.query as { before: number }).before).toBe(51);
  });
});

describe("Activity page without blocked-connection logging", () => {
  it("says so under the empty list in portable mode", async () => {
    mockDaemon({ activity: () => [], status: () => ({ ...status, portable: true, drop_events: false }) });
    renderWithProviders(<ActivityPage />);
    expect(await screen.findByText("Nothing happened yet.")).toBeInTheDocument();
    expect(await screen.findByText(/Blocked connections are not logged/)).toBeInTheDocument();
  });
});

describe("Activity page filters", () => {
  it("an empty result under a filter says so and offers to clear it", async () => {
    mockDaemon({ activity: () => [] });
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />);
    expect(await screen.findByText("Nothing happened yet.")).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText("address contains…"), "10.0.0.1");
    expect(await screen.findByText("Nothing matches these filters.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByText("Nothing happened yet.")).toBeInTheDocument();
  });
});
