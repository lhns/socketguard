import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import type { ChangesRequest } from "../api";
import { alice, batch, detail, memoryStorage, mkApp, mkPeer, mockDaemon, renderWithProviders } from "../test/helpers";

const nginx = mkApp("a1", "nginx", [80]);
const bob = mkPeer("p2", "bob");

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function setup() {
  return mockDaemon({
    list_apps: () => [nginx],
    get_app: () => detail(nginx),
    list_peers: () => [alice, bob],
    changes: (a) => batch(a.req as ChangesRequest),
  });
}
const applied = (d: ReturnType<typeof mockDaemon>) =>
  d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest).filter((r) => !r.dry_run).map((r) => r.ops);

async function openForm(user: ReturnType<typeof userEvent.setup>) {
  renderWithProviders(<AppsPage />);
  await user.click(await within(screen.getByRole("table", { name: "Apps and tags" })).findByRole("button", { name: /^nginx/ }));
  await user.click(await screen.findByRole("button", { name: "Add access to All ports" }));
  return screen.getByRole("form", { name: "Add access" });
}

describe("the who field", () => {
  it("is a text input; the list opens on focus and typing, there is no Choose who… button", async () => {
    setup();
    const user = userEvent.setup();
    const form = await openForm(user);
    expect(within(form).queryByRole("button", { name: /Choose who/ })).not.toBeInTheDocument();
    const who = within(form).getByRole("combobox", { name: "Who" });
    expect(who).toHaveAttribute("placeholder", "Peer, group, Anyone — or paste a key or address");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    await user.click(who);
    expect(await screen.findByRole("option", { name: /Anyone/ })).toBeInTheDocument();
    await user.type(who, "bo");
    expect(screen.getByRole("option", { name: /bob/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /alice/ })).not.toBeInTheDocument();
  });

  it("Enter picks the highlighted row and shows it as a chip", async () => {
    setup();
    const user = userEvent.setup();
    const form = await openForm(user);
    await user.type(within(form).getByRole("combobox", { name: "Who" }), "bo{Enter}");
    expect(within(form).getByRole("list", { name: "Chosen subjects" })).toHaveTextContent("bob");
  });

  it("a pasted value offers a new peer, which is created in the same batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    const form = await openForm(user);
    await user.type(within(form).getByRole("combobox", { name: "Who" }), "10.0.0.7");
    await user.click(await screen.findByRole("option", { name: /New peer from/ }));
    expect(within(form).getByText("new peer")).toBeInTheDocument();
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toMatchObject([{ op: "create_peer", credentials: [{ kind: "ip", value: "10.0.0.7" }] }, { op: "add_grant", subject: { kind: "peer", id: "$new0" } }]);
  });
});

describe("the network chips", () => {
  const chip = (form: HTMLElement, name: string) => within(within(form).getByRole("group", { name: "Networks" })).getByRole("button", { name });

  it("All networks is selected by default; a specific network replaces it and the last one brings it back", async () => {
    setup();
    const user = userEvent.setup();
    const form = await openForm(user);
    expect(chip(form, "All networks")).toHaveAttribute("aria-pressed", "true");
    expect(chip(form, "LAN")).toHaveAttribute("aria-pressed", "false");

    await user.click(chip(form, "LAN"));
    expect(chip(form, "All networks")).toHaveAttribute("aria-pressed", "false");
    expect(chip(form, "LAN")).toHaveAttribute("aria-pressed", "true");
    await user.click(chip(form, "Yggdrasil"));
    expect(chip(form, "Yggdrasil")).toHaveAttribute("aria-pressed", "true");

    await user.click(chip(form, "All networks"));
    expect(chip(form, "All networks")).toHaveAttribute("aria-pressed", "true");
    expect(chip(form, "LAN")).toHaveAttribute("aria-pressed", "false");
    expect(chip(form, "Yggdrasil")).toHaveAttribute("aria-pressed", "false");

    await user.click(chip(form, "LAN"));
    await user.click(chip(form, "LAN"));
    expect(chip(form, "All networks")).toHaveAttribute("aria-pressed", "true");
  });

  it("All networks sends one grant without a network", async () => {
    const d = setup();
    const user = userEvent.setup();
    const form = await openForm(user);
    await user.type(within(form).getByRole("combobox", { name: "Who" }), "bo{Enter}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0]).toHaveLength(1);
    expect(applied(d)[0][0]).not.toHaveProperty("network_id");
  });

  it("two chosen networks send one grant each", async () => {
    const d = setup();
    const user = userEvent.setup();
    const again = await openForm(user);
    await user.type(within(again).getByRole("combobox", { name: "Who" }), "bo{Enter}");
    await user.click(chip(again, "LAN"));
    await user.click(chip(again, "Yggdrasil"));
    await user.click(within(again).getByRole("button", { name: "Add access" }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].map((o) => (o as { network_id?: string }).network_id).sort()).toEqual(["n-lan", "n-ygg"]);
  });

  it("the form is ordered who, what, where, button", async () => {
    setup();
    const user = userEvent.setup();
    const form = await openForm(user);
    const who = within(form).getByRole("combobox", { name: "Who" });
    const what = within(form).getByRole("group", { name: "What to open" });
    const where = within(form).getByRole("group", { name: "Networks" });
    const submit = within(form).getByRole("button", { name: "Add access" });
    const before = (a: Node, b: Node) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(before(who, what)).toBe(true);
    expect(before(what, where)).toBe(true);
    expect(before(where, submit)).toBe(true);
  });
});
