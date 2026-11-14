# ADR 0066: Adding a Network Asks Before Grants to Anyone Take Effect on It

## Status

Accepted. Refines ADR 0027 and ADR 0061.

## Date

2026-11-14

## Context

A grant without a network applies to every network on which grants apply, and a grant row may name an id that no network serves (removing a network deletes the grants that name it, but nothing stops a row from naming an id that is not configured), so adding a network makes existing grants take effect on it at once. A grant to Anyone then opens its app to everyone on the new network, with no question: every other change that opens something to Anyone needs `confirm_open`, and the frontends show who gains access first.

## Decision

- `Engine::add_network` works out, before it creates, writes or starts anything, which existing grants let someone in on the new network, with the code that computes every other reach (`ReachCtx::reach_of`, on the network as it will appear: its kind, whether grants apply, its id). A grant counts when its reach there is not `NotReachable`. A grant on a row bound to a reservation does nothing on Tor and Local on loopback takes no grants, so neither is listed or asked about.
- If a grant to Anyone is among them, the add is refused with `confirmation_required` unless `NewNetwork.confirm_open` is set. Building the network object is in memory only, so a refusal leaves no network, key, address or log line.
- `NewNetwork.dry_run` makes `POST /api/networks` validate as the real add does, change nothing and answer 200 with a `NetworkAddPreview` `{gains, confirm_open_required}`; each gain is a `BatchChange` (the label, `opens_to_anyone`, and the grant's reach on the new network only), the type the frontends already show for a batch. No new route.
- When grants take effect through an add, a `network_changed` activity says how many (and how many are to Anyone).
- The CLI (`networks add`, `init`) and the UI (network cards, Advanced form) preview first, list the gains, and ask only when Anyone is among them (`--yes`, or the warning form of the review dialog).

## Consequences

- Nothing opens to Anyone unasked by adding a network, including one added under an id that grant rows already name.
- A script that adds a network on a host with a grant to Anyone must pass `--yes`; the package tests do.
- The preview and the add each compute the gains, so a grant made between them is caught by the add's own check (the frontends then look again).
- IPv4 reach of a new interface is judged with the current protect-host interfaces; this only matters for which grants are listed, never for whether Anyone needs the question.
