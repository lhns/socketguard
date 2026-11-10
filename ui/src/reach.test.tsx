import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { CREDENTIAL_INFO, CredentialBadge, REACH_INFO, ReachBadge } from "./reach";
import type { CredentialKind, Reach } from "./api";

describe("reach badges", () => {
  const cases: [Reach, string][] = [
    ["verified", "verified by key"],
    ["whole_subnet", "whole subnet"],
    ["ip_only", "IP only"],
    ["open", "open to anyone"],
    ["unfiltered", "open to everyone over IPv4"],
    ["not_reachable", "not reachable here"],
  ];

  it.each(cases)("renders %s with its label and a tooltip", (reach, label) => {
    render(<ReachBadge reach={reach} network="Yggdrasil" />);
    const badge = screen.getByText(`Yggdrasil: ${label}`);
    expect(badge).toHaveAttribute("title", REACH_INFO[reach].tip);
    expect(badge.getAttribute("title")).not.toBe("");
  });

  it("covers every Reach value", () => {
    expect(Object.keys(REACH_INFO).sort()).toEqual(cases.map(([r]) => r).sort());
  });

  const creds: [CredentialKind, string][] = [
    ["ygg_key", "verified"],
    ["ygg_addr", "verified"],
    ["ygg_subnet", "whole subnet"],
    ["ip", "IP only"],
    ["ip_suffix", "IP only"],
    ["wg_key", "stored, not enforced yet"],
    ["tor_client_key", "verified by key"],
    ["tls_spki", "stored, not enforced yet"],
  ];
  it.each(creds)("credential %s is badged %s", (kind, label) => {
    render(<CredentialBadge kind={kind} />);
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(CREDENTIAL_INFO[kind].label).toBe(label);
  });
});
