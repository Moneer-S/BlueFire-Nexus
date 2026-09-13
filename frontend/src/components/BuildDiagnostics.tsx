import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Button, DataList, ErrorState, LoadingState } from "./Primitives";

export function BuildDiagnostics() {
  const query = useQuery({ queryKey: ["build-info"], queryFn: api.buildInfo, retry: false });
  const info = query.data;
  return <section className="settings-build" aria-labelledby="build-diagnostics-title">
    <h2 id="build-diagnostics-title">About this service</h2>
    {query.isPending ? <LoadingState label="Loading package details"/> : null}
    {query.isError ? <ErrorState title="Package details unavailable" error={query.error} retry={() => query.refetch()}/> : null}
    {info ? <>
      {query.isError ? <p>Previously loaded details. The current service could not be checked.</p> : null}
      <p>{info.product.name} {info.product.version}</p>
      <p>{info.ui.matches_build === true ? "Packaged UI files match this build." : info.ui.matches_build === false ? "Packaged UI files differ from the recorded build. Reinstall the intended package and relaunch the service." : "This package has no usable build record to verify its UI files."}</p>
      <details><summary>Build and asset identity</summary>
        <p>These details describe the running service and its packaged files. They do not identify a cached browser page or uncommitted source changes.</p>
        <DataList items={[
          {label:"Recorded revision", value:<code>{info.source.revision ?? "Unavailable"}</code>},
          {label:"Build record", value:info.build.metadata_status},
          {label:"Build digest", value:<code>{info.build.digest ?? "Unavailable"}</code>},
          {label:"Packaged UI digest", value:<code>{info.ui.digest ?? "Unavailable"}</code>},
        ]}/>
        {info.ui.files.map(file => <p key={file.name}><strong>{file.name}</strong> · {file.size.toLocaleString()} bytes<br/><code>{file.sha256}</code></p>)}
      </details>
    </> : null}
    <Button variant="ghost" size="small" disabled={query.isFetching} onClick={() => query.refetch()}>Refresh package details</Button>
  </section>;
}
