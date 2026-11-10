import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import PeersPage from "./PeersPage";
import type { ChangesRequest } from "../api";
import { mockDaemon, renderWithProviders, saved } from "../test/helpers";

const KEY = "b".repeat(64);
const batch = (a: Record<string, unknown>) => {
  const req = a.req as ChangesRequest;
  return saved({ dry_run: req.dry_run, refs: {}, changes: [] });
};
const sent = (d: ReturnType<typeof mockDaemon>) => d.calls.filter((c) => c.cmd === "changes").map((c) => (c.args.req as ChangesRequest).ops);

async function paste(user: ReturnType<typeof userEvent.setup>, text: string) {
  // user.type would treat "{" and "[" specially; paste is what people do.
  const box = await screen.findByLabelText("Keys, addresses or IPs");
  await user.click(box);
  await user.paste(text);
}

describe("Peers page", () => {
  it("adds a peer with a key through the batch endpoint", async () => {
    const d = mockDaemon({ changes: batch });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, KEY);
    await user.type(screen.getByLabelText("Label"), "bob");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(d.count("changes")).toBe(1));
    expect(sent(d)[0]).toEqual([
      { op: "create_peer", ref: "$new0", label: "bob", credentials: [{ kind: "ygg_key", value: KEY, label: null }] },
    ]);
  });

  it("shows a chip per pasted value and adds all of them to one peer", async () => {
    const d = mockDaemon({ changes: batch });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, `10.0.0.1, fd00::1\n${KEY}`);
    const chips = await screen.findByRole("list", { name: "Parsed values" });
    await waitFor(() => expect(within(chips).getAllByRole("listitem")).toHaveLength(3));
    expect(within(chips).getAllByText("IP")).toHaveLength(2);
    expect(within(chips).getByText("Yggdrasil key")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Label"), "multi");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    await waitFor(() => expect(d.count("changes")).toBe(1));
    expect(sent(d)[0]).toMatchObject([
      { op: "create_peer", label: "multi", credentials: [{ value: "10.0.0.1" }, { value: "fd00::1" }, { value: KEY }] },
    ]);
  });

  it("can make one peer per pasted value, in one batch", async () => {
    const d = mockDaemon({ changes: batch });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, "10.0.0.1 10.0.0.2");
    await user.click(screen.getByRole("checkbox", { name: /One peer per value/ }));
    await user.click(screen.getByRole("button", { name: "Add peers" }));
    await waitFor(() => expect(d.count("changes")).toBe(1));
    expect(sent(d)[0]).toMatchObject([
      { op: "create_peer", ref: "$new0", label: "10.0.0.1" },
      { op: "create_peer", ref: "$new1", label: "10.0.0.2" },
    ]);
  });

  it("shows the parser's error at the values and sends nothing", async () => {
    const d = mockDaemon({ changes: batch });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, "not-an-ip");
    await user.type(screen.getByLabelText("Label"), "bob");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    expect((await screen.findAllByRole("alert"))[0]).toHaveTextContent('cannot tell what "not-an-ip" is');
    expect(d.count("changes")).toBe(0);
  });

  it("puts a label conflict at the label field", async () => {
    mockDaemon({
      changes: () => {
        throw { code: "conflict", message: "operation 0: peer label already in use", details: null };
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await paste(user, "10.0.0.1");
    await user.type(screen.getByLabelText("Label"), "alice");
    await user.click(screen.getByRole("button", { name: "Add peer" }));
    const err = await screen.findByText("peer label already in use");
    expect(err.closest(".form-row")).toContainElement(screen.getByLabelText("Label"));
  });

  it("lists credentials with badges", async () => {
    mockDaemon();
    renderWithProviders(<PeersPage />);
    expect(await screen.findByText("verified")).toBeInTheDocument();
  });

  it("generates a Tor access key and shows the private key once", async () => {
    const d = mockDaemon({
      generate_tor_key: () =>
        saved({ credential: { id: "c9", kind: "tor_client_key", value: "ABC", label: null }, private_key: "PRIVATEKEY123" }),
    });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    await user.click(await screen.findByRole("button", { name: "Generate Tor access key" }));
    const dialog = await screen.findByRole("dialog", { name: "Tor access key for alice" });
    expect(within(dialog).getByTestId("tor-private-key")).toHaveTextContent("PRIVATEKEY123");
    expect(d.last("generate_tor_key")?.args).toEqual({ peerId: "p1" });
    await user.click(within(dialog).getByRole("button", { name: "I have copied it" }));
    expect(screen.queryByTestId("tor-private-key")).not.toBeInTheDocument();
  });

  it("creates, edits and deletes groups", async () => {
    const group = { id: "g1", label: "team", members: [], created_at: "" };
    const d = mockDaemon({
      list_groups: () => [group],
      create_group: () => ({ ...group, id: "g2", label: "ops" }),
      set_group_members: () => saved({ ...group, members: ["p1"] }),
      delete_group: () => saved(null),
    });
    const user = userEvent.setup();
    renderWithProviders(<PeersPage />);
    // Create.
    const form = (await screen.findByRole("heading", { name: "New group" })).closest("form")!;
    await user.type(within(form).getByLabelText("Group name"), "ops");
    await user.click(within(form).getByRole("checkbox", { name: "alice" }));
    await user.click(within(form).getByRole("button", { name: "Create group" }));
    await waitFor(() => expect(d.count("create_group")).toBe(1));
    expect(d.last("create_group")?.args.req).toEqual({ label: "ops", members: ["p1"] });
    // Change members of the existing group.
    const card = screen.getByRole("group", { name: "Group team" });
    await user.click(within(card).getByRole("checkbox", { name: "alice" }));
    await user.click(within(card).getByRole("button", { name: "Save group" }));
    await waitFor(() => expect(d.count("set_group_members")).toBe(1));
    expect(d.last("set_group_members")?.args).toEqual({ id: "g1", peerIds: ["p1"] });
    // Delete.
    await user.click(within(card).getByRole("button", { name: "Delete group team" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Delete group team?" })).getByRole("button", { name: "Delete group" }));
    await waitFor(() => expect(d.count("delete_group")).toBe(1));
  });
});
