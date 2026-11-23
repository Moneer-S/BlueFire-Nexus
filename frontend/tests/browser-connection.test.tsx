import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { BrowserConnection } from "../src/components/BrowserConnection";
import * as api from "../src/lib/api";

beforeEach(() => { window.history.replaceState({}, "", "/"); });

it("requires an explicit valid one-time code and bounds duplicate submissions", async () => {
  let finish!: () => void;
  const establish = vi.spyOn(api, "establishBrowserSession").mockImplementation(() => new Promise<void>(resolve => { finish = resolve; }));
  const connected = vi.fn(); render(<BrowserConnection connected={connected} />);
  const input = screen.getByLabelText(/One-time connection code/);
  const button = screen.getByRole("button", { name: "Connect" });
  expect(establish).not.toHaveBeenCalled(); expect(button).toBeDisabled();
  fireEvent.change(input, { target: { value: "invalid" } }); expect(button).toBeDisabled();
  fireEvent.change(input, { target: { value: "C".repeat(64) } }); fireEvent.click(button);
  expect(establish).toHaveBeenCalledExactlyOnceWith("", "C".repeat(64));
  expect(input).toBeDisabled(); expect(screen.getByRole("button", { name: "Connecting" })).toBeDisabled();
  await act(async () => { finish(); });
  expect(connected).toHaveBeenCalledOnce(); expect(input).toHaveValue("");
});

it("clears failed codes, shows only a safe error and accepts a fresh retry", async () => {
  const secret = "C".repeat(64);
  const establish = vi.spyOn(api, "establishBrowserSession").mockRejectedValueOnce(new Error(secret)).mockResolvedValueOnce(undefined);
  const connected = vi.fn(); render(<BrowserConnection connected={connected} />);
  const input = screen.getByLabelText(/One-time connection code/);
  fireEvent.change(input, { target: { value: secret } });
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Connect" })); });
  expect(screen.getByRole("alert")).toHaveTextContent("Relaunch BlueFire for a fresh code.");
  expect(screen.getByRole("alert")).not.toHaveTextContent(secret); expect(input).toHaveValue("");
  fireEvent.change(input, { target: { value: "N".repeat(64) } });
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Connect" })); });
  expect(establish).toHaveBeenCalledTimes(2); expect(connected).toHaveBeenCalledOnce();
});
