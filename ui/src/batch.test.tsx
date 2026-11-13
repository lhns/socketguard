import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ChangeList } from "./batch";
import type { BatchChange, Network } from "./api";

const lan: Network = { id: "n-lan", kind: "lan", name: "LAN", interface: "eth0", grants_apply: true, status: { state: "up" } };
const NOTE = "Apps that match these patterns later will be open to Anyone without asking again.";

describe("ChangeList", () => {
  it("shows the note the daemon puts on a grant to Anyone on a tag with patterns", () => {
    const change: BatchChange = {
      kind: "create", item: "grant", name: "Anyone to tag web", opens_to_anyone: true,
      reach: [{ network_id: "n-lan", reach: "open", note: NOTE }],
    };
    render(<ChangeList changes={[change]} networks={[lan]} />);
    expect(screen.getByText(new RegExp(NOTE))).toBeInTheDocument();
  });
});
