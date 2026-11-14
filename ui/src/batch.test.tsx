import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ChangeList } from "./batch";
import type { BatchChange, Network } from "./api";
import { networks } from "./test/helpers";

const lan: Network = { id: "n-lan", kind: "lan", name: "LAN", interface: "eth0", grants_apply: true, status: { state: "up" } };
const NOTE = "Apps that match these patterns later will be open to Anyone without asking again.";
const grant: BatchChange = { kind: "create", item: "grant", name: "alice to nginx", opens_to_anyone: false, reach: [] };

describe("ChangeList", () => {
  it("shows the note the daemon puts on a grant to Anyone on a tag with patterns", () => {
    const change: BatchChange = {
      kind: "create", item: "grant", name: "Anyone to tag web", opens_to_anyone: true,
      reach: [{ network_id: "n-lan", reach: "open", note: NOTE }],
    };
    render(<ChangeList changes={[change]} networks={[lan]} />);
    expect(screen.getByText(new RegExp(NOTE))).toBeInTheDocument();
  });

  it("says a new grant is not reachable yet while no network takes grants", () => {
    render(<ChangeList changes={[grant]} networks={[networks[0]]} />);
    expect(screen.getByText("not reachable yet: no network takes grants")).toBeInTheDocument();
  });

  it("does not say so when a network takes grants", () => {
    render(<ChangeList changes={[grant]} networks={networks} />);
    expect(screen.queryByText(/not reachable yet/)).not.toBeInTheDocument();
  });
});
