import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Split from "./Split";
import { memoryStorage } from "../test/helpers";

const KEY = "socketguard.split.test";
let storage = memoryStorage();

beforeEach(() => {
  storage = memoryStorage();
  vi.stubGlobal("localStorage", storage);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const page = (props: Partial<React.ComponentProps<typeof Split>> = {}) =>
  render(
    <Split id="test" {...props}>
      <section aria-label="List">list</section>
      <section aria-label="Details">details</section>
    </Split>,
  );
const handle = () => screen.getByRole("separator", { name: "Resize details" });
const now = () => Number(handle().getAttribute("aria-valuenow"));

describe("the split between the list and the inspector", () => {
  it("is a focusable separator with its value and limits", () => {
    page();
    expect(handle()).toHaveAttribute("tabindex", "0");
    expect(handle()).toHaveAttribute("aria-orientation", "vertical");
    expect(now()).toBeGreaterThanOrEqual(300);
    expect(Number(handle().getAttribute("aria-valuemax"))).toBeGreaterThan(now());
  });

  it("the arrow keys resize it (left widens the inspector) and the width is remembered", async () => {
    const user = userEvent.setup();
    page();
    const before = now();
    handle().focus();
    await user.keyboard("{ArrowLeft}{ArrowLeft}");
    expect(now()).toBe(before + 48);
    await user.keyboard("{ArrowRight}");
    expect(now()).toBe(before + 24);
    expect(storage.getItem(KEY)).toBe(String(before + 24));
  });

  it("stops at the minimum width of both sides", async () => {
    const user = userEvent.setup();
    page();
    handle().focus();
    await user.keyboard("{Home}");
    expect(now()).toBe(300);
    await user.keyboard("{ArrowRight}");
    expect(now()).toBe(300);
    await user.keyboard("{End}");
    const max = Number(handle().getAttribute("aria-valuemax"));
    expect(now()).toBe(max);
    await user.keyboard("{ArrowLeft}");
    expect(now()).toBe(max);
  });

  it("a dragged width is applied and remembered", () => {
    page();
    fireEvent.mouseDown(handle(), { clientX: 700 });
    fireEvent.mouseMove(document, { clientX: 600 });
    fireEvent.mouseUp(document);
    // The container's right edge is the window's when jsdom has no layout.
    expect(now()).toBe(window.innerWidth - 600 - 8);
    expect(storage.getItem(KEY)).toBe(String(window.innerWidth - 600 - 8));
  });

  it("starts from the remembered width, clamped to the window, and again after a resize", () => {
    storage.setItem(KEY, "5000");
    page();
    const max = Number(handle().getAttribute("aria-valuemax"));
    expect(now()).toBe(max);

    cleanup();
    storage.setItem(KEY, "450");
    vi.spyOn(window, "innerWidth", "get").mockReturnValue(1024);
    page();
    expect(now()).toBe(450);
    vi.spyOn(window, "innerWidth", "get").mockReturnValue(700);
    act(() => void window.dispatchEvent(new Event("resize")));
    expect(now()).toBe(Number(handle().getAttribute("aria-valuemax")));
    expect(now()).toBeLessThan(450);
  });

  it("double-click resets to the default and forgets the width", async () => {
    const user = userEvent.setup();
    page();
    const start = now();
    handle().focus();
    await user.keyboard("{ArrowLeft}");
    expect(storage.getItem(KEY)).not.toBeNull();
    await user.dblClick(handle());
    expect(now()).toBe(start);
    expect(storage.getItem(KEY)).toBeNull();
  });

  it("has no handle while the inspector is a strip or closed", () => {
    const { rerender } = page({ collapsed: true });
    expect(screen.queryByRole("separator")).not.toBeInTheDocument();
    rerender(
      <Split id="test" closed>
        <section aria-label="List">list</section>
      </Split>,
    );
    expect(screen.queryByRole("separator")).not.toBeInTheDocument();
  });

  it("works when storage is unavailable", async () => {
    vi.stubGlobal("localStorage", { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } });
    const user = userEvent.setup();
    page();
    const before = now();
    handle().focus();
    await user.keyboard("{ArrowLeft}");
    expect(now()).toBe(before + 24);
  });
});
