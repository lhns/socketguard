import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Picker, { type PickerItem } from "./Picker";

const items: PickerItem[] = [
  { id: "web", label: "web", state: "on" },
  { id: "data", label: "data", state: "mixed" },
  { id: "admin", label: "admin", state: "off" },
];

function Harness({ onToggle = () => {}, onCreate = () => {} }: { onToggle?: (i: PickerItem) => void; onCreate?: (t: string) => void }) {
  const [log, setLog] = useState("");
  return (
    <>
      <Picker
        label="Tags"
        trigger="Tags…"
        items={items}
        onToggle={(i) => {
          setLog(`toggled ${i.id}`);
          onToggle(i);
        }}
        create={(typed) => ({ label: <>Create &ldquo;{typed}&rdquo;</>, pick: () => onCreate(typed) })}
      />
      <p data-testid="log">{log}</p>
    </>
  );
}

describe("Picker", () => {
  it("opens with the search field focused and lists checkbox rows with a mixed state", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Tags…" }));
    expect(screen.getByRole("combobox", { name: "Search Tags" })).toHaveFocus();
    const web = screen.getByRole("checkbox", { name: "web" });
    const data = screen.getByRole("checkbox", { name: "data" });
    expect(web).toBeChecked();
    expect(data).not.toBeChecked();
    expect((data as HTMLInputElement).indeterminate).toBe(true);
    expect(data).toHaveAttribute("aria-checked", "mixed");
    expect(screen.getByRole("checkbox", { name: "admin" })).not.toBeChecked();
  });

  it("filters as you type and offers to create what is not there", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Tags…" }));
    await user.type(screen.getByRole("combobox"), "ad");
    expect(screen.getByRole("checkbox", { name: "admin" })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: "web" })).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: /Create .ad./ })).toBeInTheDocument();
    // An exact name is not offered again.
    await user.clear(screen.getByRole("combobox"));
    await user.type(screen.getByRole("combobox"), "web");
    expect(screen.queryByRole("option", { name: /Create/ })).not.toBeInTheDocument();
  });

  it("Enter picks the highlighted row; the arrow keys move; Enter on the create row creates", async () => {
    const user = userEvent.setup();
    const onToggle = vi.fn();
    const onCreate = vi.fn();
    render(<Harness onToggle={onToggle} onCreate={onCreate} />);
    await user.click(screen.getByRole("button", { name: "Tags…" }));
    await user.keyboard("{Enter}");
    expect(onToggle).toHaveBeenLastCalledWith(expect.objectContaining({ id: "web" }));
    await user.keyboard("{ArrowDown}{ArrowDown}{Enter}");
    expect(onToggle).toHaveBeenLastCalledWith(expect.objectContaining({ id: "admin" }));
    await user.keyboard("{ArrowUp}{Enter}");
    expect(onToggle).toHaveBeenLastCalledWith(expect.objectContaining({ id: "data" }));

    await user.type(screen.getByRole("combobox"), "staging{Enter}");
    expect(onCreate).toHaveBeenCalledWith("staging");
    expect(onToggle).toHaveBeenCalledTimes(3);
  });

  it("Escape and a click outside close it", async () => {
    const user = userEvent.setup();
    render(<><Harness /><button>elsewhere</button></>);
    await user.click(screen.getByRole("button", { name: "Tags…" }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Tags…" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "Tags…" }));
    expect(screen.getByRole("combobox")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "elsewhere" }));
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  });

  it("clicking a row toggles it", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("button", { name: "Tags…" }));
    await user.click(screen.getByRole("checkbox", { name: "admin" }));
    expect(screen.getByTestId("log")).toHaveTextContent("toggled admin");
  });
});
