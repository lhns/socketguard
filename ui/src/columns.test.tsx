import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useColumns } from "./columns";
import { memoryStorage } from "./test/helpers";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the chosen columns", () => {
  it("are kept in storage and shared by every user of the hook", () => {
    const storage = memoryStorage();
    vi.stubGlobal("localStorage", storage);
    const a = renderHook(() => useColumns());
    const b = renderHook(() => useColumns());
    act(() => a.result.current.add("peer:p1"));
    act(() => a.result.current.add("peer:p1"));
    act(() => b.result.current.set(["peer:p1", "anyone"]));
    expect(a.result.current.keys).toEqual(["peer:p1", "anyone"]);
    expect(JSON.parse(storage.getItem("socketguard.columns")!)).toEqual(["peer:p1", "anyone"]);
  });

  it("ignore a damaged stored value", () => {
    const storage = memoryStorage();
    storage.setItem("socketguard.columns", "{not json");
    vi.stubGlobal("localStorage", storage);
    expect(renderHook(() => useColumns()).result.current.keys).toEqual([]);
    storage.setItem("socketguard.columns", JSON.stringify([1, "anyone", null]));
    expect(renderHook(() => useColumns()).result.current.keys).toEqual(["anyone"]);
  });

  it("still work for the session when storage is blocked", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
    });
    const { result } = renderHook(() => useColumns());
    expect(result.current.keys).toEqual([]);
    act(() => result.current.add("group:g1"));
    expect(result.current.keys).toEqual(["group:g1"]);
    act(() => result.current.set([]));
  });
});
