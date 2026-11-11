import { api, type ExposureResponse, type NetworkExposure } from "../api";
import { errorText } from "../lib";
import { elevatedFailure } from "./ElevatedAction";

/** The networks whose software keeps running, so that they stay reachable without the block. */
export function exposedNetworks(e: ExposureResponse | undefined): NetworkExposure[] {
  return e?.networks.filter((n) => n.node_running) ?? [];
}

/** Whether setup started a service that this notice can offer to stop. */
export function stoppable(exposed: NetworkExposure[]): boolean {
  return exposed.some((n) => n.services_started_by_setup.length > 0);
}

/** Stop the service setup started (an elevated command). Returns why it did not, or null. */
export async function stopStartedService(configPath: string | undefined): Promise<string | null> {
  if (!configPath) return "The daemon did not say where its config file is, so the service cannot be stopped from here.";
  try {
    const r = await api.stopSetupService("yggdrasil", configPath);
    const failure = elevatedFailure(r);
    if (failure === null) return null;
    return `${failure} The service was not stopped.${r.launched ? "" : ` ${r.command}`}`;
  } catch (e) {
    return errorText(e);
  }
}

/**
 * What stays reachable when SocketGuard stops blocking a network (ADR 0051), shown before the
 * person confirms. Nothing when no node keeps running.
 */
export default function ExposureNotice({
  exposure,
  stop,
  onStop,
}: {
  exposure: ExposureResponse | undefined;
  stop: boolean;
  onStop: (stop: boolean) => void;
}) {
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
      {stoppable(exposed) ? (
        <label className="check">
          <input type="checkbox" checked={stop} onChange={(e) => onStop(e.target.checked)} /> Also stop the Yggdrasil service
        </label>
      ) : (
        <p>To close it, stop the Yggdrasil service yourself (on Windows: Services, or <code>sc stop Yggdrasil</code>; elsewhere <code>systemctl stop yggdrasil</code>).</p>
      )}
    </div>
  );
}
