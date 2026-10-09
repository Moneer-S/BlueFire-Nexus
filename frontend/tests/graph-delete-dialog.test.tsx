import { useRef, type RefObject } from "react";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { GraphDeleteDialog } from "../src/components/GraphDeleteDialog";
import { useGraphDeletion } from "../src/state/useGraphDeletion";

type Item = { id: string };
type Deletion = ReturnType<typeof useGraphDeletion<Item, Item>>;
const elements = { nodes: [{ id: "selected-step" }], edges: [{ id: "selected-route" }] };
const description = { steps: ["Collect bounded system facts"], connections: ["On success → Stage selected records"] };

function Harness({ revision, scope = "visible-selection", readOnly = false, showOrigin = true, current, resolved, liveRevision }: {
  revision: object; scope?: string; readOnly?: boolean; showOrigin?: boolean;
  current: RefObject<Deletion | null>;
  resolved: (result: typeof elements | false) => void;
  liveRevision?: RefObject<object>;
}) {
  const fallback = useRef<HTMLButtonElement>(null);
  const deletion = useGraphDeletion<Item, Item>({ revision, scope, readOnly,
    currentRevision: () => liveRevision?.current ?? revision, focusFallback: () => fallback.current,
    focusContainer: () => fallback.current?.parentElement ?? null, removalCommitted: () => !showOrigin });
  current.current = deletion;
  return <>
    {showOrigin ? <button onClick={() => { void deletion.request(elements, description).then(resolved); }}>Delete selection</button> : null}
    <button ref={fallback}>Graph fallback</button>
    <GraphDeleteDialog summary={deletion.summary} confirm={deletion.confirm} cancel={deletion.cancel} restoreFocus={deletion.restoreFocus} />
  </>;
}

function setup(options: Partial<Parameters<typeof Harness>[0]> = {}) {
  const props = { revision: {}, current: { current: null } as RefObject<Deletion | null>, resolved: vi.fn(), ...options };
  return { props, ...render(<Harness {...props} />) };
}

it("settles an Escape cancellation, restores the trigger, and refuses duplicate requests", async () => {
  const user = userEvent.setup();
  const { props } = setup();
  const trigger = screen.getByRole("button", { name: "Delete selection" });
  await user.click(trigger);
  const dialog = await screen.findByRole("dialog", { name: "Delete from experiment?" });
  expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
  expect(props.current.current!.allowsRemoval("nodes", "selected-step")).toBe(false);
  expect(await props.current.current!.request(elements, description)).toBe(false);
  expect(screen.getAllByRole("dialog")).toHaveLength(1);
  await user.keyboard("{Escape}");
  await waitFor(() => expect(props.resolved).toHaveBeenCalledExactlyOnceWith(false));
  await waitFor(() => expect(trigger).toHaveFocus());
  expect(props.current.current!.consume(elements)).toBe(false);
});

it("confirms only the reviewed elements once, and restores a fallback after its trigger disappears", async () => {
  const user = userEvent.setup();
  const view = setup();
  await user.click(screen.getByRole("button", { name: "Delete selection" }));
  view.rerender(<Harness {...view.props} showOrigin={false} />);
  await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(view.props.resolved).toHaveBeenCalledExactlyOnceWith(elements));
  const deletion = view.props.current.current!;
  expect(deletion.allowsRemoval("nodes", "selected-step")).toBe(true);
  expect(deletion.allowsRemoval("edges", "selected-route")).toBe(true);
  expect(deletion.allowsRemoval("nodes", "unreviewed-step")).toBe(false);
  expect(deletion.allowsRemoval("edges", "unreviewed-route")).toBe(false);
  expect(deletion.consume(elements)).toBe(true);
  expect(deletion.consume(elements)).toBe(false);
  expect(deletion.allowsRemoval("nodes", "selected-step")).toBe(false);
  view.rerender(<Harness {...view.props} revision={{}} showOrigin={false} />);
  await waitFor(() => expect(screen.getByRole("button", { name: "Graph fallback" })).toHaveFocus());
});

it.each(["revision", "scope", "read-only"])("cancels a pending review after a changed %s and rejects its stale callback", async (change) => {
  const user = userEvent.setup();
  const view = setup();
  const staleRequest = view.props.current.current!.request;
  await user.click(screen.getByRole("button", { name: "Delete selection" }));
  expect(await screen.findByRole("dialog")).toBeVisible();
  const next = { ...view.props, ...(change === "revision" ? { revision: {} } : change === "scope" ? { scope: "other-section" } : { readOnly: true }) };
  view.rerender(<Harness {...next} />);
  await waitFor(() => expect(view.props.resolved).toHaveBeenCalledExactlyOnceWith(false));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(await staleRequest(elements, description)).toBe(false);
  expect(view.props.current.current!.consume(elements)).toBe(false);
});

it("settles a pending request on unmount and never restores the departed editor's focus", async () => {
  const user = userEvent.setup();
  const view = setup();
  await user.click(screen.getByRole("button", { name: "Delete selection" }));
  expect(await screen.findByRole("dialog")).toBeVisible();
  const deletion = view.props.current.current!;
  view.unmount();
  await waitFor(() => expect(view.props.resolved).toHaveBeenCalledExactlyOnceWith(false));
  const destination = document.createElement("button");
  document.body.append(destination);
  destination.focus();
  deletion.restoreFocus();
  expect(destination).toHaveFocus();
  expect(await deletion.request(elements, description)).toBe(false);
  destination.remove();
});

it("refuses a graph replaced after confirmation but before asynchronous removal", async () => {
  const user = userEvent.setup();
  const revision = {};
  const liveRevision = { current: revision };
  const view = setup({ revision, liveRevision, resolved: () => { liveRevision.current = {}; } });
  await user.click(screen.getByRole("button", { name: "Delete selection" }));
  await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete" }));
  const deletion = view.props.current.current!;
  expect(deletion.allowsRemoval("nodes", "selected-step")).toBe(false);
  expect(deletion.allowsRemoval("edges", "selected-route")).toBe(false);
  expect(deletion.consume(elements)).toBe(false);
});

it("refuses a removal whose elements differ from the confirmed selection", async () => {
  const user = userEvent.setup();
  const view = setup();
  await user.click(screen.getByRole("button", { name: "Delete selection" }));
  await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete" }));
  await act(async () => {
    expect(view.props.current.current!.consume({ nodes: [], edges: elements.edges })).toBe(false);
    expect(view.props.current.current!.consume(elements)).toBe(false);
  });
});
