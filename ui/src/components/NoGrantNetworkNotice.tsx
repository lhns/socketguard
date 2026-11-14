import { useNav } from "../nav";
import { useNetworks } from "../queries";

/** True once the networks are known and none of them takes grants (only Local, which is on loopback). */
export function useNoGrantNetwork(): boolean {
  const networks = useNetworks();
  return networks.data !== undefined && !networks.data.some((n) => n.grants_apply);
}

/** Shown wherever access is given while no network takes grants: it can be set up now and
 * takes effect once a network is added. Renders nothing otherwise. */
export default function NoGrantNetworkNotice() {
  const nav = useNav();
  const none = useNoGrantNetwork();
  if (!none) return null;
  return (
    <div className="warn-banner banner" role="status" data-testid="no-grant-network">
      <span>
        No network takes grants yet, so nobody can reach anything beyond this machine. Access set here takes effect once a network is
        added (LAN, Yggdrasil or Tor).
      </span>
      <button type="button" className="btn btn-sm" onClick={() => nav.go("settings")}>Add a network</button>
    </div>
  );
}
