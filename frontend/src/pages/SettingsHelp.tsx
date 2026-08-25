import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { BookOpen, Download, FileJson2, Github, KeyRound, LifeBuoy, LockKeyhole, Moon, RotateCcw, Save, ShieldCheck, Sun, Upload } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import {
  buildUiPreferenceDocument,
  parseUiPreferenceDocument,
  readBrowserTheme,
  readBrowserUiPreferences,
  useProduct,
  writeBrowserUiPreferences,
  type UiTheme,
} from "../state/ProductContext";
import { Badge, Button, Callout, DataList, Field, PageHeader, Panel, PanelHeader } from "../components/Primitives";

function readTextFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("The preference file could not be read."));
    reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("The preference file was not text."));
    reader.readAsText(file);
  });
}

export function SettingsPage() {
  const { runConfig, setRunConfig } = useProduct();
  const [theme, setTheme] = useState<UiTheme>(() => readBrowserUiPreferences()?.theme ?? readBrowserTheme());
  const fileRef = useRef<HTMLInputElement>(null);
  const [notice, setNotice] = useState<string>();
  const hydrated = useRef(false);
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: api.settings });

  useEffect(() => {
    if (hydrated.current || !settingsQuery.data) return;
    hydrated.current = true;
    const value = settingsQuery.data.settings.find((item) => item.key === "ui.preferences")?.value;
    if (!value) return;
    try {
      const preferences = parseUiPreferenceDocument(value);
      setTheme(preferences.theme);
      setRunConfig({ ...runConfig, mode: preferences.effect_mode, autonomy: preferences.autonomy, approved: false, approvedBy: "" });
    } catch (error) {
      setNotice(`Durable preferences were ignored. ${error instanceof Error ? error.message : "The preference document was invalid."}`);
    }
  }, [runConfig, setRunConfig, settingsQuery.data]);

  useEffect(() => {
    window.localStorage.setItem("bluefire.theme", theme);
    writeBrowserUiPreferences(buildUiPreferenceDocument(theme, runConfig.mode, runConfig.autonomy));
    const resolved = theme === "system" ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme;
    document.documentElement.dataset.theme = resolved;
  }, [runConfig.autonomy, runConfig.mode, theme]);

  const preferenceDocument = () => buildUiPreferenceDocument(theme, runConfig.mode, runConfig.autonomy);
  const saveMutation = useMutation({
    mutationFn: () => api.saveSetting("ui.preferences", preferenceDocument()),
    onSuccess: ({ setting }) => setNotice(`Preferences saved durably at ${new Date(setting.updated_at).toLocaleString()}. Execute approval remained cleared.`),
    onError: (error) => setNotice(error instanceof Error ? error.message : "Preferences could not be saved."),
  });
  const exportSettings = () => {
    const url = URL.createObjectURL(new Blob([`${JSON.stringify(preferenceDocument(), null, 2)}\n`], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "bluefire-ui-preferences.json";
    link.click();
    URL.revokeObjectURL(url);
  };
  const importSettings = async (file?: File) => {
    if (!file) return;
    try {
      const preferences = parseUiPreferenceDocument(JSON.parse(await readTextFile(file)) as unknown);
      setTheme(preferences.theme);
      setRunConfig({ ...runConfig, mode: preferences.effect_mode, autonomy: preferences.autonomy, approved: false, approvedBy: "" });
      setNotice("Theme, effect mode, and autonomy were imported into this form. No authority fields were accepted; review and save these preferences.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Import failed.");
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return <div className="page settings-page">
    <PageHeader
      eyebrow="Application configuration"
      title="Settings"
      description="Manage exactly three non-authoritative UI preferences: theme, preferred effect mode, and preferred AI autonomy."
      actions={<>
        <input aria-label="Import UI preferences file" className="sr-only" ref={fileRef} type="file" accept="application/json" onChange={(event) => importSettings(event.target.files?.[0])} />
        <Button variant="secondary" onClick={() => fileRef.current?.click()}><Upload />Import</Button>
        <Button variant="secondary" onClick={exportSettings}><Download />Export</Button>
        <Button variant="primary" onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}><Save />{saveMutation.isPending ? "Saving" : "Save settings"}</Button>
      </>}
    />
    {notice ? <Callout title="Settings">{notice}</Callout> : settingsQuery.isError ? <Callout tone="warning" title="Durable settings unavailable">The form is using browser preferences. Save after the local service is ready.</Callout> : null}
    <div className="settings-grid">
      <Panel>
        <PanelHeader eyebrow="Appearance" title="Workspace theme" />
        <div className="detail-body"><div className="theme-picker">{(["dark", "light", "system"] as UiTheme[]).map((item) => <button key={item} className={theme === item ? "selected" : ""} onClick={() => setTheme(item)}>{item === "dark" ? <Moon /> : item === "light" ? <Sun /> : <RotateCcw />}<span><strong>{item[0]!.toUpperCase() + item.slice(1)}</strong><small>{item === "system" ? "Follow operating system" : `${item} interface`}</small></span></button>)}</div></div>
      </Panel>
      <Panel>
        <PanelHeader eyebrow="Preference defaults" title="New run starting choices" />
        <div className="detail-body">
          <Field label="Effect mode"><select value={runConfig.mode} onChange={(event) => setRunConfig({ ...runConfig, mode: event.target.value as "simulate" | "execute", approved: false, approvedBy: "" })}><option value="simulate">Simulate</option><option value="execute">Execute</option></select></Field>
          <Field label="AI autonomy"><select value={runConfig.autonomy} onChange={(event) => setRunConfig({ ...runConfig, autonomy: event.target.value as typeof runConfig.autonomy })}><option value="off">Off</option><option value="assist">Assist</option><option value="auto">Auto</option></select></Field>
          <Callout title="Starting choices, not authority">These preferences initialize a new run form. The selected canonical profile and preflight still determine effective safety, scope, policy, budgets, cleanup, capabilities, and action allowlists.</Callout>
          <Callout title="Approval never persists">Execute confirmation and operator identity are cleared on load and import and are never part of saved preferences.</Callout>
        </div>
      </Panel>
      <Panel>
        <PanelHeader eyebrow="Durable effect" title="Strict preference schema" />
        <div className="detail-body">
          <DataList items={[
            { label: "Theme", value: "Applied immediately and restored locally" },
            { label: "Effect mode", value: "Starting choice for a new preflight form" },
            { label: "AI autonomy", value: "Starting choice for a new preflight form" },
            { label: "Import and export", value: "Round-trips only this versioned three-preference schema" },
            { label: "Everything else", value: "Never persisted or imported by this page" },
          ]} />
          <Callout title="Operational authority stays canonical">Provider, model, profile, scope, safety, approval, budgets, collectors, detection backends, cleanup, counterfactuals, fixtures, action implementations, identity, and endpoint are excluded from browser, durable, imported, and exported preferences.</Callout>
        </div>
      </Panel>
      <Panel>
        <PanelHeader eyebrow="Integrations" title="Secret references" />
        <div className="detail-body">
          <div className="secret-row"><span><KeyRound /></span><div><strong>OPENAI_API_KEY</strong><small>Environment reference · value never read by browser</small></div><Badge tone="neutral">Not checked</Badge></div>
          <div className="secret-row"><span><LockKeyhole /></span><div><strong>BLUEFIRE_RUNNER_BINARY</strong><small>Runner boundary reference · resolved server-side</small></div><Badge tone="neutral">Not checked</Badge></div>
          <Callout title="No plaintext secret fields">Provider tokens, runner credentials, and backend credentials must be resolved at the boundary that needs them.</Callout>
        </div>
      </Panel>
    </div>
  </div>;
}

const helpCards = [
  { title: "First Simulate run", icon: ShieldCheck, to: "/runs", text: "Open a scenario, validate the graph, choose Simulate with AI Off, review preflight, then inspect synthetic evidence." },
  { title: "Prepare Execute", icon: LockKeyhole, to: "/runners", text: "Register a runner record, verify the executor outside the browser, select an Execute profile and scope, then review the exact approval envelope." },
  { title: "Tune a detection", icon: FileJson2, to: "/detection-lab", text: "Link a behavior hypothesis, parse with an authoritative backend when available, exercise fixtures, attach observed evidence, and evaluate benign records." },
  { title: "Replay a defense change", icon: RotateCcw, to: "/compare", text: "Select an immutable source run, declare the defense change, choose an available safe replay strategy, then compare canonical deltas." },
];

export function HelpPage() {
  return <div className="page help-page"><PageHeader eyebrow="Documentation & support" title="Help center" description="Operate BlueFire safely, understand evidence semantics, and troubleshoot missing runners, collectors, providers, and detection backends." actions={<a href="https://github.com/Moneer-S/BlueFire-Nexus" target="_blank" rel="noreferrer"><Button variant="secondary"><Github />Repository</Button></a>} />
    <div className="help-grid">{helpCards.map((card) => { const Icon = card.icon; return <Panel key={card.title}><Icon /><h2>{card.title}</h2><p>{card.text}</p><Link to={card.to}><Button size="small" variant="ghost">Open workflow</Button></Link></Panel>; })}</div>
    <div className="two-column"><Panel><PanelHeader eyebrow="Core concepts" title="Know what each record proves" /><div className="concept-list"><div><Badge tone="info">Synthetic</Badge><p>Modeled or fixture-generated evidence. It is not proof of execution.</p></div><div><Badge tone="warning">Executed</Badge><p>A runner reports that an action started or completed. It is not independent observation.</p></div><div><Badge tone="success">Observed</Badge><p>An independent declared collector attributed an observable to the experiment.</p></div><div><Badge tone="warning">Control blocked</Badge><p>A control or policy prevented the requested path; this is a valuable outcome.</p></div><div><Badge tone="violet">Counterfactual</Badge><p>A modeled continuation after a real path stopped. It must remain visibly distinct.</p></div></div></Panel><Panel><PanelHeader eyebrow="Troubleshooting" title="Common readiness problems" /><details className="help-details"><summary>Execute preflight says runner unavailable</summary><p>Confirm the Rust runner binary reference, sandbox root, identity, version compatibility, profile attachment, and advertised actions. Do not change to a broader scope to make preflight pass.</p></details><details className="help-details"><summary>AI provider is not healthy</summary><p>Use AI Off for deterministic operation. Verify only the environment-variable reference, endpoint, model, timeout, and provider health; never paste a secret into the UI.</p></details><details className="help-details"><summary>Observed evidence is missing</summary><p>Runner receipts are executed evidence. Enable and verify an independent collector, inspect its health and timeout, then replay if the environment is still authorized.</p></details><details className="help-details"><summary>A rendered detection did not match</summary><p>Parsing, fixture exercise, observed exercise, and benign evaluation are separate lifecycle stages. Inspect field mapping and telemetry prerequisites before tuning.</p></details></Panel></div>
    <Panel><PanelHeader eyebrow="Quick navigation" title="Continue in the product" /><div className="quick-links"><Link to="/scenarios"><BookOpen />Choose a scenario</Link><Link to="/builder"><FileJson2 />Build the graph</Link><Link to="/runs"><ShieldCheck />Configure a run</Link><Link to="/detection-lab"><LifeBuoy />Open Detection Lab</Link></div></Panel>
  </div>;
}
