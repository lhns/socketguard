import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { createQueryClient } from "./queries";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ToastProvider } from "./components/Toast";
import "./styles.css";
import "./inspector.css";

const queryClient = createQueryClient();

async function start() {
  // Development only: `?mock` runs the frontend on fake daemon data in a plain browser. The
  // condition is false in a production build, so the mock is not bundled.
  if (import.meta.env.DEV && new URLSearchParams(window.location.search).has("mock")) {
    (await import("./dev/mock")).installMock();
  }
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <ErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <ToastProvider>
            <App />
          </ToastProvider>
        </QueryClientProvider>
      </ErrorBoundary>
    </React.StrictMode>
  );
}

void start();
