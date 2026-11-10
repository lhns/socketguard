import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import PeersPage from "./PeersPage";
import { alice, mockDaemon, renderWithProviders } from "../test/helpers";

describe("Peers page", () => {
  it("guesses a Yggdrasil key from 64 hex characters", async () => {
    const d = mockDaemon({ create_peer: () => alice });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.type(await screen.findByLabelText("Label"), "bob");
    await user.type(screen.getByLabelText("Key, address or IP"), "b".repeat(64));
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(d.count("create_peer")).toBe(1));
    expect(d.last("create_peer")?.args.req).toEqual({
      label: "bob",
      credentials: [{ kind: "ygg_key", value: "b".repeat(64), label: null }],
    });
  });

  it("sends an IP or CIDR as kind ip", async () => {
    const d = mockDaemon({ create_peer: () => alice });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.type(await screen.findByLabelText("Label"), "lan");
    await user.type(screen.getByLabelText("Key, address or IP"), "10.0.0.0/24");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(d.count("create_peer")).toBe(1));
    expect(d.last("create_peer")?.args.req).toMatchObject({
      credentials: [{ kind: "ip", value: "10.0.0.0/24" }],
    });
  });

  it("previews what the parser made of the input and adds several values", async () => {
    const d = mockDaemon({ create_peer: () => alice });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.type(await screen.findByLabelText("Label"), "multi");
    await user.type(screen.getByLabelText("Key, address or IP"), "10.0.0.1, fd00::1");
    expect(await screen.findByText(/10\.0\.0\.1 will be added as IP/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(d.count("create_peer")).toBe(1));
    expect(d.last("create_peer")?.args.req).toMatchObject({
      credentials: [{ kind: "ip", value: "10.0.0.1" }, { kind: "ip", value: "fd00::1" }],
    });
  });

  it("shows the parser's error and does not create the peer", async () => {
    const d = mockDaemon({ create_peer: () => alice });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.type(await screen.findByLabelText("Label"), "bob");
    await user.type(screen.getByLabelText("Key, address or IP"), "not-an-ip");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    expect(await screen.findByRole("alert")).toHaveTextContent('cannot tell what "not-an-ip" is');
    expect(d.count("create_peer")).toBe(0);
  });

  it("shows the daemon's validation error", async () => {
    mockDaemon({
      create_peer: () => {
        throw { code: "invalid", message: "peer label already in use", details: null };
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.type(await screen.findByLabelText("Label"), "bob");
    await user.type(screen.getByLabelText("Key, address or IP"), "10.0.0.1");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("peer label already in use");
  });

  it("lists credentials with badges and points to the CLI for groups", async () => {
    mockDaemon();
    renderWithProviders(<PeersPage />);
    expect(await screen.findByText("verified")).toBeInTheDocument();
    expect(screen.getByText("socketguard groups")).toBeInTheDocument();
  });
});
