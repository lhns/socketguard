import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup, configure } from "@testing-library/react";
import { clearMocks } from "@tauri-apps/api/mocks";

// The whole suite runs in parallel jsdom workers; a page's first render can take over a second.
configure({ asyncUtilTimeout: 4000 });

afterEach(() => {
  cleanup();
  clearMocks();
});
