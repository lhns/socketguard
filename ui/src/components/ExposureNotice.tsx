import type { ExposureResponse, NetworkExposure } from "../api";

/** The networks whose software keeps running, so that they stay reachable without the block. */
export function exposedNetworks(e: ExposureResponse | undefined): NetworkExposure[] {
  return e?.networks.filter((n) => n.node_running) ?? [];
}

/**
 * What stays reachable when SocketGuard stops blocking a network (ADR 0051), shown before the
 * person confirms. Nothing when no node keeps running.
 */
export default function ExposureNotice({ exposure }: { exposure: ExposureResponse | undefined }) {
  const exposed = exposedNetworks(exposure);
  if (exposed.length === 0) return null;
  // The listeners are the host's, the same for every network.
  const listeners = exposed[0].listeners;
  const programs = listeners.map((l) => `${l.app} (port ${l.port}/${l.proto})`).join(", ");
  return (
    <div className="hint warn" role="alert" aria-label="What becomes reachable">
      {listeners.length > 0 ? (
        <p>
          Yggdrasil keeps running. Without SocketGuard, {listeners.length} {listeners.length === 1 ? "program" : "programs"} on this PC{" "}
          {listeners.length === 1 ? "is" : "are"} reachable over it: {programs}.
        </p>
      ) : (
        <p>Yggdrasil keeps running. No program listens on all addresses now, but any that starts will be reachable over it.</p>
      )}
      <p>
        SocketGuard does not run this node, so it keeps running and this PC stays reachable over it until you stop the Yggdrasil service yourself (on
        Windows: Services, or <code>sc stop Yggdrasil</code>; elsewhere <code>systemctl stop yggdrasil</code>).
      </p>
    </div>
  );
}
