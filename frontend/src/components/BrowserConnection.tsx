import { Flame, Link2, LoaderCircle } from "lucide-react";
import { useState, type FormEvent } from "react";
import { establishBrowserSession } from "../lib/api";
import { Button, Field } from "./Primitives";
import "./BrowserConnection.css";

export function BrowserConnection({ connected }: { connected: () => void }) {
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);
  const valid = /^[A-Za-z0-9_-]{64}$/.test(code);
  async function connect(event: FormEvent) {
    event.preventDefault();
    if (!valid || pending) return;
    setPending(true); setFailed(false);
    try {
      await establishBrowserSession("", code);
      setCode(""); connected();
    } catch { setCode(""); setFailed(true); }
    finally { setPending(false); }
  }
  return <main className="browser-connection">
    <header><Flame aria-hidden="true" /><h1>BlueFire Nexus</h1></header>
    <h2>Connect to your workspace</h2>
    <form onSubmit={connect}>
      <Field label="One-time connection code" hint="From the terminal that launched BlueFire.">
        <input type="password" value={code} maxLength={64} autoComplete="off" spellCheck={false}
          disabled={pending} onChange={event => { setCode(event.target.value.trim()); setFailed(false); }} />
      </Field>
      {failed ? <p role="alert">This code is unavailable or expired. Relaunch BlueFire for a fresh code.</p> : null}
      <Button type="submit" variant="primary" disabled={!valid || pending}>
        {pending ? <LoaderCircle className="spin" aria-hidden="true" /> : <Link2 aria-hidden="true" />}
        {pending ? "Connecting" : "Connect"}
      </Button>
    </form>
  </main>;
}
