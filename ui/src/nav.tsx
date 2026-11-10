// Page navigation, shared by the shell and the pages that link to each other (a tag on an app, an
// activity row to its app). Pages stay mounted, so a link only tells the target what to show.
import { createContext, useContext } from "react";

export type Page = "apps" | "peers" | "activity" | "settings";

/** What a page should show when it is opened by a link rather than by the tab. */
export interface Focus {
  appId?: string;
  tagId?: string;
  search?: string;
  pendingOnly?: boolean;
  peerId?: string;
  groupId?: string;
}

/** A link's focus; `seq` changes with every link, so the same focus twice still counts. */
export type FocusMessage = Focus & { seq: number };

interface NavContextValue {
  go: (page: Page, focus?: Focus) => void;
}

export const NavContext = createContext<NavContextValue>({ go: () => {} });
export const useNav = () => useContext(NavContext);
