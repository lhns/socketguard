import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AppsPage from "./AppsPage";
import { appDetail, grantView, mockDaemon, renderWithProviders } from "../test/helpers";

async function openGrantDialog() {
  const user = userEvent.setup();
  renderWithProviders(<AppsPage />);
  await user.click(await screen.findByRole("button", { name: /nginx/ }));
  await user.click(await screen.findByRole("button", { name: "Grant access…" }));
  return { user, dialog: await screen.findByRole("dialog", { name: "Grant access" }) };
}

describe("Apps page", () => {
  it("lists apps with a pending badge, and shows grant chips with reach badges", async () => {
    mockDaemon({
      get_app: () => ({
        ...appDetail,
        grants: [
          grantView({
            reach: [
              { network_id: "n-ygg", reach: "verified" },
              { network_id: "n-lan", reach: "not_reachable" },
            ],
          }),
        ],
      }),
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    const row = await screen.findByRole("button", { name: /nginx/ });
    expect(within(row).getByText("pending")).toBeInTheDocument();
    await user.click(row);
    expect(await screen.findByText("Yggdrasil: verified by key")).toBeInTheDocument();
    expect(screen.getByText("LAN: not reachable here")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke access for alice" })).toBeInTheDocument();
  });

  it("grants a peer without a confirmation", async () => {
    const d = mockDaemon({ create_grant: () => grantView() });
    const { user, dialog } = await openGrantDialog();
    await user.selectOptions(within(dialog).getByLabelText("Who"), "alice");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    await waitFor(() => expect(d.count("create_grant")).toBe(1));
    expect(d.last("create_grant")?.args.req).toMatchObject({
      target: { kind: "app", id: "a1" },
      subject: { kind: "peer", id: "p1" },
      confirm_open: false,
      port: null,
    });
  });

  it("asks before opening to Anyone and sends confirm_open", async () => {
    const d = mockDaemon({ create_grant: () => grantView({ subject: { kind: "anyone" } }) });
    const { user, dialog } = await openGrantDialog();
    await user.selectOptions(within(dialog).getByLabelText("Who"), "Anyone");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    expect(d.count("create_grant")).toBe(0);
    await user.click(within(confirm).getByRole("button", { name: "Open to anyone" }));
    await waitFor(() => expect(d.count("create_grant")).toBe(1));
    expect(d.last("create_grant")?.args.req).toMatchObject({ subject: { kind: "anyone" }, confirm_open: true });
  });

  it("words the Anyone confirmation for a network as everyone on it, and sends the network", async () => {
    const d = mockDaemon({ create_grant: () => grantView({ subject: { kind: "anyone" }, network_id: "n-lan" }) });
    const { user, dialog } = await openGrantDialog();
    await user.selectOptions(within(dialog).getByLabelText("Who"), "Anyone");
    await user.selectOptions(within(dialog).getByLabelText("Network"), "LAN");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to everyone on LAN?" });
    await user.click(within(confirm).getByRole("button", { name: "Open to everyone on LAN" }));
    await waitFor(() => expect(d.count("create_grant")).toBe(1));
    expect(d.last("create_grant")?.args.req).toMatchObject({ network_id: "n-lan", confirm_open: true });
  });

  it("badges a network-scoped Anyone grant as a segment", async () => {
    mockDaemon({
      get_app: () => ({
        ...appDetail,
        grants: [grantView({ subject: { kind: "anyone" }, network_id: "n-lan", reach: [{ network_id: "n-lan", reach: "open" }] })],
      }),
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await screen.findByRole("button", { name: /nginx/ }));
    expect(await screen.findByText("segment")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke access for Everyone on LAN" })).toBeInTheDocument();
  });

  it("cancelling the Anyone confirmation grants nothing", async () => {
    const d = mockDaemon();
    const { user, dialog } = await openGrantDialog();
    await user.selectOptions(within(dialog).getByLabelText("Who"), "Anyone");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    await user.click(within(confirm).getByRole("button", { name: "Cancel" }));
    expect(d.count("create_grant")).toBe(0);
  });

  it("handles a confirmation_required answer by confirming and retrying", async () => {
    let n = 0;
    const d = mockDaemon({
      create_grant: (args) => {
        n++;
        if (!(args.req as { confirm_open: boolean }).confirm_open) {
          throw { code: "confirmation_required", message: "confirm opening to anyone", details: null };
        }
        return grantView();
      },
    });
    const { user, dialog } = await openGrantDialog();
    await user.selectOptions(within(dialog).getByLabelText("Who"), "alice");
    await user.click(within(dialog).getByRole("button", { name: "Grant" }));
    const confirm = await screen.findByRole("dialog", { name: "Open to anyone?" });
    await user.click(within(confirm).getByRole("button", { name: "Open to anyone" }));
    await waitFor(() => expect(n).toBe(2));
    expect(d.last("create_grant")?.args.req).toMatchObject({ confirm_open: true });
  });

  it("shows this machine only for a Local-only app, without a grant list", async () => {
    mockDaemon({
      get_app: () => ({ ...appDetail, addresses: [{ ...appDetail.addresses[0], network_id: "n-local" }] }),
    });
    const user = userEvent.setup();
    renderWithProviders(<AppsPage />);
    await user.click(await screen.findByRole("button", { name: /nginx/ }));
    expect(await screen.findByText(/This machine only\. Grants do not apply/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Grant access…" })).not.toBeInTheDocument();
  });
});
