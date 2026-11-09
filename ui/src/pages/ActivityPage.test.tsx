import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ActivityPage from "./ActivityPage";
import { alice, mockDaemon, renderWithProviders } from "../test/helpers";
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
  it("keeps a discovered app closed", async () => {
    const d = mockDaemon({ activity: () => [rec({})], review_app: () => ({}) });
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />);
    expect(await screen.findByText("nginx is listening")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Keep closed" }));
    await waitFor(() => expect(d.count("review_app")).toBe(1));
    expect(d.last("review_app")?.args).toEqual({ id: "a1", reviewed: true });
  });

  it("grants a blocked source by creating an IP peer first", async () => {
    const d = mockDaemon({
      activity: () => [
        rec({ id: 2, kind: "blocked", src: "192.0.2.9", port: 8080, proto: "tcp", message: "blocked 192.0.2.9" }),
      ],
      create_peer: () => ({ ...alice, id: "p9", label: "192.0.2.9" }),
      create_grant: () => ({}),
    });
    const user = userEvent.setup();
    renderWithProviders(<ActivityPage />);
    await user.click(await screen.findByRole("button", { name: "Grant this source…" }));
    const dialog = await screen.findByRole("dialog", { name: "Grant 192.0.2.9 access" });
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(d.count("create_grant")).toBe(1));
    expect(d.last("create_peer")?.args.req).toEqual({
      label: "192.0.2.9",
      credentials: [{ kind: "ip", value: "192.0.2.9", label: null }],
    });
    expect(d.last("create_grant")?.args.req).toMatchObject({
      app_id: "a1",
      subject: { kind: "peer", id: "p9" },
    });
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
