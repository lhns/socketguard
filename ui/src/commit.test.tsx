import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { BatchChange, ChangeOp, ChangesRequest, PeerGroup } from "./api";
import CommitPreview from "./components/CommitPreview";
import { useCommit } from "./commit";
import { alice, batch, grantView, mkGroup, mkPeer, mockDaemon, renderWithProviders } from "./test/helpers";

function Harness({ ops, undo }: { ops: ChangeOp[]; undo?: ChangeOp[] }) {
  const commit = useCommit();
  return (
    <>
      <button onClick={() => void commit.runBatch(ops, "Did it", undo)}>go</button>
      <CommitPreview commit={commit} />
    </>
  );
}

const grantOp: ChangeOp = { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "all" }, subject: { kind: "peer", id: "p1" }, confirm_open: false };
const anyoneOp: ChangeOp = { op: "add_grant", target: { kind: "app", id: "a1" }, scope: { kind: "all" }, subject: { kind: "anyone" }, confirm_open: false };
const created: BatchChange = { kind: "create", item: "grant", name: "alice to nginx", opens_to_anyone: false, reach: [{ network_id: "n-ygg", reach: "verified" }] };

const requests = (d: ReturnType<typeof mockDaemon>) => d.calls.filter((c) => c.cmd === "changes").map((c) => c.args.req as ChangesRequest);

describe("the commit rule", () => {
  it("applies at once when nobody gains access", async () => {
    const d = mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, false) });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[{ op: "review", app_id: "a1", reviewed: true }]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    expect(await screen.findByText("Did it")).toBeInTheDocument();
    expect(requests(d).map((r) => r.dry_run)).toEqual([true, false]);
    expect(screen.queryByRole("region", { name: "Review before applying" })).not.toBeInTheDocument();
  });

  it("shows ONE dialog with the changes when somebody gains access, and applies on its button", async () => {
    const d = mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, true, [created]) });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[grantOp]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    const dialog = await screen.findByRole("dialog", { name: "Give access?" });
    expect(within(dialog).getByText("alice to nginx")).toBeInTheDocument();
    expect(within(dialog).getByText(/Yggdrasil: verified by key/)).toBeInTheDocument();
    expect(requests(d)).toHaveLength(1);
    expect(requests(d)[0].dry_run).toBe(true);

    await user.click(within(dialog).getByRole("button", { name: "Give access" }));
    expect(await screen.findByText("Did it")).toBeInTheDocument();
    expect(requests(d).map((r) => r.dry_run)).toEqual([true, false]);
    expect(requests(d)[1].ops).toMatchObject([{ confirm_open: false }]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("there is no inline review", async () => {
    mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, true, [created]) });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[grantOp]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    await screen.findByRole("dialog");
    expect(screen.queryByRole("region", { name: "Review before applying" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Apply" })).not.toBeInTheDocument();
  });

  it("Cancel drops the dialog without applying", async () => {
    const d = mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, true, [created]) });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[grantOp]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(requests(d)).toHaveLength(1);
  });

  it("opening to Anyone is the same dialog with a warning and a button named after what it opens", async () => {
    const opening: BatchChange = { ...created, name: "Anyone to nginx 443/tcp", opens_to_anyone: true };
    const d = mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, true, [opening]) });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[anyoneOp]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    const dialog = await screen.findByRole("dialog", { name: /Open nginx 443\/tcp to anyone/ });
    expect(within(dialog).getByRole("note")).toHaveTextContent("This opens nginx 443/tcp to anyone on every network that takes grants.");
    expect(within(dialog).getByText("Anyone to nginx 443/tcp")).toBeInTheDocument();
    // The dry run was sent confirmed (it saves nothing); nothing is applied before the answer.
    expect(requests(d)).toHaveLength(1);
    expect(requests(d)[0].ops).toMatchObject([{ confirm_open: true }]);

    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(requests(d)).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "go" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Open nginx 443/tcp to anyone" }));
    expect(await screen.findByText("Did it")).toBeInTheDocument();
    expect(requests(d).filter((r) => !r.dry_run)).toHaveLength(1);
    expect(requests(d).filter((r) => !r.dry_run)[0].ops).toMatchObject([{ confirm_open: true }]);
  });

  it("a 409 on apply shows the same dialog in its Anyone form", async () => {
    let applies = 0;
    const d = mockDaemon({
      changes: (a) => {
        const req = a.req as ChangesRequest;
        if (req.dry_run) return batch(req, false);
        applies++;
        if (!(req.ops[0] as { confirm_open: boolean }).confirm_open) throw { code: "confirmation_required", message: "confirm it" };
        return batch(req, false);
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[{ op: "add_tag_member", tag_id: "t1", app_id: "a1", scope: { kind: "all" }, confirm_open: false }]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("note")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: /^Open .* to anyone$/ }));
    expect(await screen.findByText("Did it")).toBeInTheDocument();
    expect(applies).toBe(2);
    expect(requests(d)[requests(d).length - 1].ops).toMatchObject([{ confirm_open: true }]);
  });

  it("an error from the apply shows inside the dialog and keeps it open", async () => {
    let fail = true;
    const d = mockDaemon({
      changes: (a) => {
        const req = a.req as ChangesRequest;
        if (!req.dry_run && fail) throw { code: "conflict", message: "operation 0: grant already exists" };
        return batch(req, true, [created]);
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[grantOp]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Give access" }));
    expect(await within(await screen.findByRole("dialog")).findByRole("alert")).toHaveTextContent("grant already exists");
    expect(screen.queryByText("Did it")).not.toBeInTheDocument();
    // It can be tried again.
    fail = false;
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Give access" }));
    expect(await screen.findByText("Did it")).toBeInTheDocument();
    expect(requests(d).filter((r) => !r.dry_run)).toHaveLength(2);
  });

  it("alwaysReview (the app transfer) uses the same dialog even when nobody gains access", async () => {
    const d = mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, false, [{ ...created, kind: "update", name: "alice: a1 to a2" }]) });
    const user = userEvent.setup();
    function Transfer() {
      const commit = useCommit();
      return (
        <>
          <button onClick={() => void commit.runBatch([grantOp], "Did it", undefined, true)}>go</button>
          <CommitPreview commit={commit} title="Transfer access to nginx?" confirmLabel="Transfer access" />
        </>
      );
    }
    renderWithProviders(<Transfer />);
    await user.click(screen.getByRole("button", { name: "go" }));
    const dialog = await screen.findByRole("dialog", { name: "Transfer access to nginx?" });
    expect(requests(d)).toHaveLength(1);
    await user.click(within(dialog).getByRole("button", { name: "Transfer access" }));
    expect(await screen.findByText("Did it")).toBeInTheDocument();
    expect(requests(d)).toHaveLength(2);
  });

  it("an edit that only closes applies at once and the toast can undo it with the inverse batch", async () => {
    const d = mockDaemon({ changes: (a) => batch(a.req as ChangesRequest, false) });
    const user = userEvent.setup();
    const g = grantView({ id: "g1", scope: { kind: "port", port: 80, proto: "tcp" }, network_id: "n-lan" });
    const inverse: ChangeOp = { op: "add_grant", target: g.target, scope: g.scope, network_id: "n-lan", subject: g.subject, confirm_open: false };
    renderWithProviders(<Harness ops={[{ op: "remove_grant", grant_id: "g1" }]} undo={[inverse]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    await user.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(requests(d)).toHaveLength(3));
    expect(requests(d)[2]).toMatchObject({ dry_run: false, ops: [{ op: "add_grant", network_id: "n-lan", scope: { port: 80 }, confirm_open: true }] });
    expect(await screen.findByText("Undone")).toBeInTheDocument();
  });

  it("shows the daemon's refusal and applies nothing", async () => {
    const d = mockDaemon({ changes: () => { throw { code: "conflict", message: "operation 0: tag web already exists" }; } });
    const user = userEvent.setup();
    renderWithProviders(<Harness ops={[{ op: "create_tag", label: "web", patterns: [] }]} />);
    await user.click(screen.getByRole("button", { name: "go" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("tag web already exists");
    expect(requests(d)).toHaveLength(1);
  });
});

function GroupHarness({ group, next }: { group: PeerGroup; next: string[] }) {
  const commit = useCommit();
  return (
    <>
      <button onClick={() => void commit.runGroupMembers(group, next, "Updated team")}>go</button>
      <CommitPreview commit={commit} title="Joining lets more in" />
    </>
  );
}

describe("the commit rule for group membership", () => {
  const team = mkGroup("g1", "team", ["p1"]);
  const bob = mkPeer("p2", "bob");
  const teamGrant = grantView({ id: "gt", subject: { kind: "group", id: "g1" } });

  it("joining a group that has grants shows who gains what, then applies", async () => {
    const d = mockDaemon({
      list_peers: () => [alice, bob],
      list_grants: () => [teamGrant],
      list_apps: () => [],
      set_group_members: () => ({ value: team, enforcement: null }),
    });
    const user = userEvent.setup();
    renderWithProviders(<GroupHarness group={team} next={["p1", "p2"]} />);
    await screen.findByRole("button", { name: "go" });
    await waitFor(() => expect(d.count("list_grants")).toBeGreaterThan(0));
    await user.click(screen.getByRole("button", { name: "go" }));
    const review = await screen.findByRole("dialog", { name: "Joining lets more in" });
    expect(review).toHaveTextContent("bob in group team");
    expect(review).toHaveTextContent(/gains access to/);
    expect(d.count("set_group_members")).toBe(0);
    await user.click(within(review).getByRole("button", { name: "Give access" }));
    await waitFor(() => expect(d.last("set_group_members")?.args).toEqual({ id: "g1", peerIds: ["p1", "p2"] }));
  });

  it("joining a group without grants applies at once", async () => {
    const d = mockDaemon({ list_peers: () => [alice, bob], list_grants: () => [], set_group_members: () => ({ value: team, enforcement: null }) });
    const user = userEvent.setup();
    renderWithProviders(<GroupHarness group={team} next={["p1", "p2"]} />);
    await user.click(await screen.findByRole("button", { name: "go" }));
    await waitFor(() => expect(d.count("set_group_members")).toBe(1));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("leaving a group applies at once and Undo restores the members", async () => {
    const d = mockDaemon({ list_peers: () => [alice, bob], list_grants: () => [teamGrant], set_group_members: () => ({ value: team, enforcement: null }) });
    const user = userEvent.setup();
    const two = mkGroup("g1", "team", ["p1", "p2"]);
    renderWithProviders(<GroupHarness group={two} next={["p1"]} />);
    await screen.findByRole("button", { name: "go" });
    await user.click(screen.getByRole("button", { name: "go" }));
    await user.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(d.count("set_group_members")).toBe(2));
    expect(d.last("set_group_members")?.args).toEqual({ id: "g1", peerIds: ["p1", "p2"] });
  });
});
