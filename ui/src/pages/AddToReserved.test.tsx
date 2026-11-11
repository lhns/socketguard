// "Add to reserved address…" on the rows of an app and on a tag, and the "+ Port group" entry.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import type { ChangesRequest, PortGroup } from "../api";
import { batch, detail, mkApp, mkReservation, mkTag, memoryStorage, mockDaemon, renderWithProviders, saved } from "../test/helpers";

const nginx = mkApp("a1", "nginx", [80, 443]);
const web = mkTag("t-web", "web", ["a1"]);
const passive: PortGroup = { id: "sg1", label: "passive", ports: [{ start: 50000, end: 51000, proto: "tcp" }], apps: ["a1"], created_at: "2026-01-01T00:00:00Z" };
const port443 = { kind: "port" as const, port: 443, proto: "tcp" as const };
const front = mkReservation("r1", "front", [{ kind: "app", app_id: "a1", scope: port443 }]);
const tagged = mkReservation("r2", "tagged", [{ kind: "tag", tag_id: "t-web" }]);

const requests = (d: ReturnType<typeof mockDaemon>) => d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest);
const applied = (d: ReturnType<typeof mockDaemon>) => requests(d).filter((r) => !r.dry_run);

function setup(over: Parameters<typeof mockDaemon>[0] = {}) {
  return mockDaemon({
    list_apps: () => [nginx],
    get_app: () => detail(nginx, { port_groups: [passive] }),
    list_tags: () => [web],
    list_port_groups: () => [passive],
    list_reservations: () => [front],
    changes: (a) => batch(a.req as ChangesRequest),
    ...over,
  });
}

const inList = () => within(screen.getByRole("table", { name: "Apps and tags" }));
const inspector = () => screen.getByRole("region", { name: "Details" });
const rowOf = (ports: HTMLElement, label: string) => within(ports).getByText(label, { selector: ".port-name" }).closest("li")!;
const ACTION = { name: "Add to reserved address…" };
async function openApp(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await inList().findByRole("button", { name: /^nginx/ }));
  return (await within(inspector()).findByRole("heading", { name: "Ports" })).closest("section")! as HTMLElement;
}

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("+ Port group", () => {
  it("is the last entry of the Ports list, dashed, and not in the section header", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user);
    const add = within(ports).getByRole("button", { name: "+ Port group" });
    expect(add).toHaveClass("btn-dashed");
    expect(add.closest("ul")).toBe(ports.querySelector(".port-list"));
    expect(add.closest("li")).toBe(ports.querySelector(".port-list")!.lastElementChild);
    expect(add.closest(".insp-section-head")).toBeNull();
  });
});

describe("Add to reserved address… on a row", () => {
  it("is on every row that is not bound, and binds the row in one batch", async () => {
    const d = setup();
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />, go);
    const ports = await openApp(user);
    for (const label of ["All ports", "80/tcp", "passive"]) expect(within(rowOf(ports, label)).getByRole("button", ACTION)).toBeInTheDocument();
    // 443/tcp is bound to "front": it says so and offers no action.
    expect(within(rowOf(ports, "443/tcp")).queryByRole("button", ACTION)).not.toBeInTheDocument();
    expect(rowOf(ports, "443/tcp")).toHaveTextContent("Reached on reserved address");

    await user.click(within(rowOf(ports, "80/tcp")).getByRole("button", ACTION));
    await user.click(await screen.findByRole("checkbox", { name: /^front/ }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].ops).toEqual([
      { op: "add_binding", reservation_id: "r1", target: { kind: "app", app_id: "a1", scope: { kind: "port", port: 80, proto: "tcp" } }, confirm_open: false },
    ]);
    expect(requests(d).filter((r) => r.dry_run)).toHaveLength(1);

    expect(await screen.findByText("Added to front")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show reserved address" }));
    expect(go).toHaveBeenCalledWith("reserved", { reservationId: "r1" });
  });

  it("Create \"<typed>\" creates the reservation with the binding in the same batch", async () => {
    const d = setup({
      changes: (a) => saved({ dry_run: (a.req as ChangesRequest).dry_run, refs: { $res: "r-new" }, changes: [], changes_reach: false }),
    });
    const go = vi.fn();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />, go);
    const ports = await openApp(user);
    await user.click(within(rowOf(ports, "All ports")).getByRole("button", ACTION));
    await user.type(await screen.findByRole("combobox", { name: "Search Reserved addresses" }), "public-web");
    await user.click(screen.getByRole("option", { name: /Create/ }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].ops).toEqual([
      { op: "create_reservation", ref: "$res", label: "public-web", bindings: [{ kind: "app", app_id: "a1", scope: { kind: "all" } }], confirm_open: false },
    ]);
    await user.click(await screen.findByRole("button", { name: "Show reserved address" }));
    expect(go).toHaveBeenCalledWith("reserved", { reservationId: "r-new" });
  });

  it("shows the reach first when the reservation has grants that let more in", async () => {
    const d = setup({ changes: (a) => batch(a.req as ChangesRequest, true, [{ kind: "update", item: "reservation", name: "front", detail: "reachable by alice", opens_to_anyone: false, reach: [] }]) });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const ports = await openApp(user);
    await user.click(within(rowOf(ports, "80/tcp")).getByRole("button", ACTION));
    await user.click(await screen.findByRole("checkbox", { name: /^front/ }));
    expect(await within(ports).findByRole("region", { name: "Review before applying" })).toHaveTextContent("reachable by alice");
    expect(applied(d)).toHaveLength(0);
  });
});

describe("Add to reserved address… on a tag", () => {
  const tagRow = async (user: ReturnType<typeof userEvent.setup>) => {
    const box = await inList().findByRole("checkbox", { name: "Select web" });
    await user.click(within(box.closest("tr")!).getByRole("button", { name: "web" }));
  };

  it("binds the tag in one batch", async () => {
    const d = setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await tagRow(user);
    await user.click(await within(inspector()).findByRole("button", ACTION));
    await user.click(await screen.findByRole("checkbox", { name: /^front/ }));
    await waitFor(() => expect(applied(d)).toHaveLength(1));
    expect(applied(d)[0].ops).toEqual([{ op: "add_binding", reservation_id: "r1", target: { kind: "tag", tag_id: "t-web" }, confirm_open: false }]);
  });

  it("is hidden when the tag is bound", async () => {
    setup({ list_reservations: () => [front, tagged] });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await tagRow(user);
    await within(inspector()).findByRole("heading", { name: "web" });
    expect(within(inspector()).queryByRole("button", ACTION)).not.toBeInTheDocument();
  });
});
