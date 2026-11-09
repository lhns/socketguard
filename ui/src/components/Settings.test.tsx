import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { mockIPC } from "@tauri-apps/api/mocks";
import Settings from "./Settings";
import { ToastProvider } from "./Toast";

describe("Settings", () => {
  it("renders the daemon config returned over mocked Tauri IPC", async () => {
    mockIPC((cmd) => {
      if (cmd === "get_config") {
        return {
          listen_addr: "127.0.0.1",
          listen_port: 7777,
          backends: [],
          poll_interval_secs: 5,
          process_filter: { mode: "denylist", patterns: [] },
        };
      }
      if (cmd === "list_backend_instances") return { available_types: [] };
      if (cmd === "list_interfaces") return { interfaces: [] };
      return undefined; // event plugin calls (listen/unlisten) etc.
    });

    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );

    expect(await screen.findByText("127.0.0.1:7777")).toBeInTheDocument();
    expect(screen.getByText("5s")).toBeInTheDocument();
  });

  it("shows an error banner when the daemon call fails", async () => {
    mockIPC((cmd) => {
      if (cmd === "get_config") throw "daemon unreachable";
      return undefined;
    });
    render(
      <ToastProvider>
        <Settings />
      </ToastProvider>,
    );
    expect(await screen.findByText(/Cannot connect to daemon/)).toBeInTheDocument();
  });
});
