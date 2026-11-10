// Page navigation and the Simple/Advanced mode, shared by the shell and the pages that link
// to each other (a matrix cell to its tag, an activity row to its app).
import { createContext, useContext } from "react";

export type Page = "apps" | "access" | "peers" | "activity" | "settings";

/** What a page should show when it is opened by a link rather than by the tab. */
export interface Focus {
  appId?: string;
  tagId?: string;
  search?: string;
  pendingOnly?: boolean;
  peerId?: string;
  groupId?: string;
}

interface NavContextValue {
  go: (page: Page, focus?: Focus) => void;
}

export const NavContext = createContext<NavContextValue>({ go: () => {} });
export const useNav = () => useContext(NavContext);

export type Mode = "simple" | "advanced";
const MODE_KEY = "socketguard.mode";

/** The remembered mode; storage may be missing or blocked, so it falls back to simple. */
export function readMode(): Mode {
  try {
    return window.localStorage.getItem(MODE_KEY) === "advanced" ? "advanced" : "simple";
  } catch {
    return "simple";
  }
}

export function writeMode(mode: Mode) {
  try {
    window.localStorage.setItem(MODE_KEY, mode);
  } catch {
    // Not remembered; the switch still works for this session.
  }
}

/** The page each mode opens on. */
export const homeOf = (mode: Mode): Page => (mode === "advanced" ? "access" : "apps");
