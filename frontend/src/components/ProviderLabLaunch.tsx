import { downloadArtifact } from "../lib/download";
import { hasRequiredDataPolicy, providerErrors, publicProvider } from "../lib/provider-authorization";
import type { PublicAIProviderConfig } from "../types";
import { Button } from "./Primitives";

/** Export only the public connection consumed by the existing prepared-lab launcher. */
export function ProviderLabLaunch({ provider, disabled, enrolled }: { provider: PublicAIProviderConfig; disabled: boolean; enrolled: boolean }) {
  const definition = publicProvider({ ...provider });
  const artifact = new Blob([`${JSON.stringify(definition, null, 2)}\n`], { type: "application/json" });
  const valid = (definition.kind === "openai_responses" || definition.kind === "chat_completions")
    && providerErrors(definition).length === 0 && hasRequiredDataPolicy(definition) && artifact.size <= 16_384;
  const download = () => {
    if (!disabled && valid) downloadArtifact(artifact, "bluefire-model-connection.json");
  };
  return <details className="settings-import-details">
    <summary>Prepare a disposable lab connection</summary>
    <p>Use this only when starting the existing isolated Linux lab. Direct connections in the current service can use the model usage review below.</p>
    <p>The download contains the exact connection above, its request limits and redaction settings, and the environment-variable name. It contains no key value or model usage authorization.</p>
    <Button disabled={disabled || !valid} onClick={download}>Download lab connection</Button>
    {!valid ? <p>Complete a supported model connection with the required data protection before downloading. The public definition must fit the launcher's 16 KiB limit.</p> : null}
    {enrolled ? <p>This session already has an enrolled connection. The download can prepare a future restart; its current authorization will not transfer.</p> : null}
    <ol>
      <li>Provide the credential through the named environment variable in the host process that launches the lab. Enter only its name in Settings.</li>
      <li>Stop active work and close the existing lab session normally. Restart with the downloaded file, keeping the same lab state directory and UI port to preserve history.</li>
      <li>In the reopened UI, verify the locked enrolled connection. Then review the permitted work, lab data and finite usage below and authorize once. Review after restarting: earlier service authorizations do not transfer.</li>
    </ol>
    <pre><code>{'python -m bluefire.prepared_lab start --state-dir "<existing lab state directory>" --port <existing UI port> --ai-provider-definition "<downloaded file>"'}</code></pre>
    <p>The launcher uses public HTTPS by default. Add <code>--ai-destination-policy explicit_endpoint</code> only for a local or private endpoint you explicitly authorize. Downloading starts no process and sends no model request. Enrollment lasts at most 15 minutes; finish or stop active work before its displayed expiry.</p>
  </details>;
}
