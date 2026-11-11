import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import { installMock } from "../dev/mock";
import type { ChangesRequest } from "../api";
import { batch, detail, memoryStorage, mkApp, mkTag, mockDaemon, renderWithProviders, networks } from "../test/helpers";

beforeEach(() => {
  vi.stubGlobal("localStorage", memoryStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const inspector = () => screen.getByRole("region", { name: "Details" });
const listTable = () => within(screen.getByRole("table", { name: "Apps and tags" }));

describe("a fresh host (?mock=fresh): about a dozen apps, nothing granted, Local plus one LAN", () => {
  it("shows no pending badge, filter or counter, and every app says closed", async () => {
    installMock("fresh");
    const { container } = renderWithProviders(<AppsPage />);
    await listTable().findByRole("button", { name: /^nginx/ });
    expect(screen.queryByText("pending")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /Pending/ })).not.toBeInTheDocument();
    const cells = Array.from(container.querySelectorAll("td.col-access"));
    expect(cells.length).toBeGreaterThan(5);
    for (const cell of cells) expect(cell).toHaveTextContent(/^closed$/);
  });

  it("offers Add access on All ports and on every port, and Add to reserved address…", async () => {
    installMock("fresh");
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("button", { name: /^nginx/ }));
    const panel = within(await screen.findByRole("region", { name: "Details" }));
    expect(await panel.findByRole("button", { name: "Add access to All ports" })).toBeInTheDocument();
    expect(panel.getByRole("button", { name: "Add access to 80/tcp" })).toBeInTheDocument();
    expect(panel.getByRole("button", { name: "Add access to 443/tcp" })).toBeInTheDocument();
    // One per row: All ports, 80/tcp, 443/tcp.
    expect(panel.getAllByRole("button", { name: "Add to reserved address…" })).toHaveLength(3);
  });

  it("the one network that takes grants needs no network chips in the form", async () => {
    installMock("fresh");
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(await screen.findByRole("region", { name: "Details" })).findByRole("button", { name: "Add access to All ports" }));
    const form = screen.getByRole("form", { name: "Add access" });
    expect(within(form).queryByRole("group", { name: "Networks" })).not.toBeInTheDocument();
  });

  it("with only a Local network configured the actions are hidden", async () => {
    const app = mkApp("a1", "nginx", [80]);
    mockDaemon({
      list_apps: () => [app],
      get_app: () => detail(app),
      list_networks: () => [networks[0]],
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("button", { name: /^nginx/ }));
    const panel = within(await screen.findByRole("region", { name: "Details" }));
    await panel.findByText(/This machine only/);
    expect(panel.queryByRole("button", { name: /^Add access/ })).not.toBeInTheDocument();
    expect(panel.queryByRole("button", { name: "Add to reserved address…" })).not.toBeInTheDocument();
  });

  it("giving the one peer access asks once, in a dialog, and nothing is reviewed inline", async () => {
    installMock("fresh");
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("button", { name: /^nginx/ }));
    await user.click(await within(await screen.findByRole("region", { name: "Details" })).findByRole("button", { name: "Add access to 443/tcp" }));
    const form = screen.getByRole("form", { name: "Add access" });
    await user.click(within(form).getByRole("combobox", { name: "Who" }));
    await user.click(screen.getByRole("checkbox", { name: "alice" }));
    await user.keyboard("{Escape}");
    await user.click(within(form).getByRole("button", { name: "Add access" }));
    const dialog = await screen.findByRole("dialog", { name: "Give access?" });
    expect(dialog).toHaveTextContent("alice to nginx 443/tcp");
    await user.click(within(dialog).getByRole("button", { name: "Give access" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByText("Access added (1)")).toBeInTheDocument();
  });
});

describe("action rows", () => {
  const nginx = mkApp("a1", "nginx", [80]);
  const web = mkTag("t1", "web", ["a1"]);
  const setup = () =>
    mockDaemon({
      list_apps: () => [nginx],
      get_app: () => detail(nginx),
      list_tags: () => [web],
      changes: (a) => batch(a.req as ChangesRequest),
    });

  it("an app row keeps its actions in one row; Forget app is alone behind a divider at the end", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("button", { name: /^nginx/ }));
    const panel = inspector();
    const row = (await within(panel).findAllByRole("group", { name: "Actions" }))[0];
    expect(within(row).getByRole("button", { name: /^Add access/ })).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Add to reserved address…" })).toBeInTheDocument();
    const forget = within(panel).getByRole("button", { name: "Forget app" });
    expect(forget.parentElement).toHaveClass("danger-zone");
    expect(forget.parentElement!.children).toHaveLength(1);
    expect(within(row).queryByRole("button", { name: "Forget app" })).not.toBeInTheDocument();
  });

  it("opening the Add access form hides the other buttons of the row", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("button", { name: /^nginx/ }));
    const row = within((await within(inspector()).findAllByRole("group", { name: "Actions" }))[0]);
    await user.click(row.getByRole("button", { name: /^Add access/ }));
    expect(row.getByRole("form", { name: "Add access" })).toBeInTheDocument();
    expect(row.queryByRole("button", { name: "Add to reserved address…" })).not.toBeInTheDocument();
    await user.click(row.getByRole("button", { name: "Cancel" }));
    expect(row.getByRole("button", { name: "Add to reserved address…" })).toBeInTheDocument();
  });

  it("the tag inspector: Add access and Add to reserved address… together, Delete tag alone at the end", async () => {
    setup();
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("checkbox", { name: "Select web" }));
    const panel = inspector();
    const row = within(await within(panel).findByRole("group", { name: "Actions" }));
    expect(row.getByRole("button", { name: "Add access…" })).toBeInTheDocument();
    expect(row.getByRole("button", { name: "Add to reserved address…" })).toBeInTheDocument();
    expect(row.queryByRole("button", { name: "Delete tag" })).not.toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Delete tag" }).parentElement).toHaveClass("danger-zone");
  });

  it("the tag's patterns are under a collapsed disclosure unless it has some", async () => {
    mockDaemon({
      list_apps: () => [nginx],
      get_app: () => detail(nginx),
      list_tags: () => [web, mkTag("t2", "auto", ["a1"], ["nginx*"])],
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await listTable().findByRole("checkbox", { name: "Select web" }));
    const summary = await within(inspector()).findByText("Advanced: add apps automatically by name");
    expect(summary.closest("details")).not.toHaveAttribute("open");
    await user.click(listTable().getByRole("checkbox", { name: "Select web" }));
    await user.click(listTable().getByRole("checkbox", { name: "Select auto" }));
    const summary2 = await within(inspector()).findByText("Advanced: add apps automatically by name");
    expect(summary2.closest("details")).toHaveAttribute("open");
  });
});
