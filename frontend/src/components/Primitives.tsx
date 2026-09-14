import * as Dialog from "@radix-ui/react-dialog";
import * as Tooltip from "@radix-ui/react-tooltip";
import { AlertCircle, CheckCircle2, Info, LoaderCircle, X } from "lucide-react";
import type { ButtonHTMLAttributes, HTMLAttributes, PropsWithChildren, ReactNode } from "react";
import { ApiError } from "../lib/api";

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return <header className="page-header">
    <div>{eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}<h1>{title}</h1>{description ? <p>{description}</p> : null}</div>
    {actions ? <div className="page-actions">{actions}</div> : null}
  </header>;
}

export function Panel({ className = "", children, ...props }: HTMLAttributes<HTMLElement>) {
  return <section className={`panel ${className}`} {...props}>{children}</section>;
}

export function PanelHeader({ eyebrow, title, detail, actions }: { eyebrow?: string; title: string; detail?: string; actions?: ReactNode }) {
  return <header className="panel-header"><div>{eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}<h2>{title}</h2>{detail ? <p>{detail}</p> : null}</div>{actions}</header>;
}

export function Badge({ children, tone = "neutral", dot = false }: PropsWithChildren<{ tone?: "neutral" | "info" | "success" | "warning" | "danger" | "violet"; dot?: boolean }>) {
  return <span className={`badge badge-${tone}`}>{dot ? <i aria-hidden="true" /> : null}{children}</span>;
}

export function Button({ variant = "secondary", size = "medium", className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "small" | "medium" }) {
  return <button className={`button button-${variant} button-${size} ${className}`} {...props} />;
}

export function IconButton({ label, children, className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return <Tooltip.Root><Tooltip.Trigger asChild><button className={`icon-button ${className}`} aria-label={label} {...props}>{children}</button></Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="tooltip" sideOffset={8}>{label}<Tooltip.Arrow className="tooltip-arrow" /></Tooltip.Content></Tooltip.Portal></Tooltip.Root>;
}

export function Field({ label, hint, error, children, className = "" }: PropsWithChildren<{ label: string; hint?: string; error?: string; className?: string }>) {
  return <label className={`field ${className}`}><span className="field-label">{label}</span>{children}{hint ? <small>{hint}</small> : null}{error ? <small className="field-error">{error}</small> : null}</label>;
}

export function Stat({ label, value, detail, tone = "info" }: { label: string; value: ReactNode; detail?: string; tone?: "info" | "success" | "warning" | "danger" }) {
  return <article className={`stat stat-${tone}`}><span>{label}</span><strong>{value}</strong>{detail ? <small>{detail}</small> : null}</article>;
}

export function Callout({ tone = "info", title, children }: PropsWithChildren<{ tone?: "info" | "success" | "warning" | "danger"; title: string }>) {
  const Icon = tone === "success" ? CheckCircle2 : tone === "danger" ? AlertCircle : Info;
  return <div className={`callout callout-${tone}`} role={tone === "danger" ? "alert" : "status"}><Icon aria-hidden="true" /><div><strong>{title}</strong><div>{children}</div></div></div>;
}

export function LoadingState({ label = "Loading workspace" }: { label?: string }) {
  return <div className="loading-state" role="status"><LoaderCircle className="spin" aria-hidden="true" /><strong>{label}</strong><span>Loading your workspace…</span></div>;
}

export function EmptyState({ icon, title, description, action }: { icon?: ReactNode; title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state">{icon}<strong>{title}</strong><p>{description}</p>{action}</div>;
}

export function ErrorState({ title, error, retry }: { title?: string; error: unknown; retry?: () => void }) {
  const message = error instanceof Error ? error.message : "An unexpected local error occurred.";
  const status = error instanceof ApiError ? error.status : undefined;
  const code = error instanceof ApiError ? error.code : undefined;
  const category = code === "browser_session_unavailable" || status === 401
    ? ["Reconnect to the workspace", "Use the current launcher's one-use browser link to reconnect."]
    : status === 403 ? ["Access not permitted", "Review the requested access and environment permissions."]
    : status === 404 ? ["Item not found", "Return to the list and select an available item."]
    : status === 409 || status === 412 ? ["This request needs a fresh review", "Refresh the selected work and review its current settings before continuing."]
    : status === 400 || status === 422 ? ["Check the request", "Correct the indicated input and try again."]
    : code === "request_timeout" || status === 408 || status === 504 ? ["The request timed out", "Check the current job or result before submitting work again."]
    : code === "service_unavailable" || status === 502 || status === 503 ? ["Local service unavailable", "Check that the launching terminal is still running, then retry."]
    : ["Could not complete the request", "Review the error and retry once its cause is resolved."];
  return <div className="error-state" role="alert"><AlertCircle aria-hidden="true" /><div><strong>{title ?? category[0]}</strong><p>{message}</p><p>{category[1]}</p>{code || status ? <details><summary>Technical details</summary>{code ? <p>Code: <code>{code}</code></p> : null}{status ? <p>HTTP status: {status}</p> : null}</details> : null}{retry ? <Button size="small" onClick={retry}>Try again</Button> : null}</div></div>;
}

export function Modal({ trigger, title, description, children }: PropsWithChildren<{ trigger: ReactNode; title: string; description?: string }>) {
  return <Dialog.Root><Dialog.Trigger asChild>{trigger}</Dialog.Trigger><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content"><div><Dialog.Title>{title}</Dialog.Title>{description ? <Dialog.Description>{description}</Dialog.Description> : null}</div><Dialog.Close asChild><button className="dialog-close" aria-label="Close dialog"><X /></button></Dialog.Close>{children}</Dialog.Content></Dialog.Portal></Dialog.Root>;
}

export function DataList({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return <dl className="data-list">{items.map((item) => <div key={item.label}><dt>{item.label}</dt><dd>{item.value}</dd></div>)}</dl>;
}

export function formatDate(value?: string) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function sentence(value: string) { return value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase()); }
