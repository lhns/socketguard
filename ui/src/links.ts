/** Pages the window may open in the system browser. The Tauri backend keeps the same list
 * (`OPEN_LINK_ALLOWED` in src-tauri/src/main.rs) and refuses anything else; keep both in step. */

/** The Tor Project's BridgeDB, where bridge lines are requested. */
export const TOR_BRIDGES_URL = "https://bridges.torproject.org/";

/** The Yggdrasil project's list of public peers. Found through the "Public Peers" link of the
 * project's configuration page, https://yggdrasil-network.github.io/configuration.html. */
export const YGG_PUBLIC_PEERS_URL = "https://github.com/yggdrasil-network/public-peers";

export const ALLOWED_LINKS: readonly string[] = [TOR_BRIDGES_URL, YGG_PUBLIC_PEERS_URL];
