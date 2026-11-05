# Strix Test-provider tool conformance

The controlled provider's v2 manifest is an **offline conformance candidate**, not an
installed Strix qualification. Product serving is closed: `APPROVED_PROFILE_DIGESTS`
is empty, and provider state refuses to start unless an independently reviewed
profile digest is enrolled in code. A manifest cannot approve its own tool hashes.
The old `observe_fixture` and four-field `summary`/`critical_issues`/`coverage`/
`next_steps` assumptions are rejected.

The [pinned Strix factory](https://raw.githubusercontent.com/usestrix/strix/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/strix/agents/factory.py)
declares 43 ordered base tools, then `finish_scan` for the headless root agent.
The pinned [OpenAI Agents SDK filesystem](https://raw.githubusercontent.com/openai/openai-agents-python/v0.19.0/src/agents/sandbox/capabilities/filesystem.py)
and [shell](https://raw.githubusercontent.com/openai/openai-agents-python/v0.19.0/src/agents/sandbox/capabilities/shell.py)
capabilities add `view_image` when enabled, `apply_patch`, `exec_command`, and
`write_stdin` when PTY support exists. The profile accepts only these source-backed
ordered suffix variants, and marks every sandbox capability tool unsupported for
fixture emission. It binds the exact ordered `name`, parameters digest, and full
function descriptor digest for every tool in a candidate capture, and requires
`strict: true` on every descriptor. Each phase carries its parameter schema so
the offline parser can reject a permissive graph or finish signature even when
the supplied hashes agree with each other. The parser also
fixes the Strix commit/tree, SDK version, root/noninteractive Chat Completions
mode, strict schemas, Test-provider/model identity, and request/response/usage
bounds.

The [pinned `view_agent_graph` tool](https://raw.githubusercontent.com/usestrix/strix/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/strix/tools/agents_graph/tools.py)
takes no model arguments. The [pinned `finish_scan` signature](https://raw.githubusercontent.com/usestrix/strix/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/strix/tools/finish/tool.py)
requires `executive_summary`, `methodology`, `technical_analysis`, and
`recommendations`. The candidate phase plan sends a graph tool turn followed by
one terminal `finish_scan` turn, with a fixed report that says no target assessment
occurred. Exact assistant-call/tool-result pairing and the real streamed SSE
tool-turn grammar remain in place. Graph result **content is not interpreted**;
these checks prove transport sequencing only, not agent, coverage, finding, or
target state.

The CLI's [model preflight](https://raw.githubusercontent.com/usestrix/strix/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/strix/interface/scan_setup.py)
is a separate no-tools `get_response` call before root-agent turns. It is not a
manifest phase and this provider does not yet serve it. The installed SDK's
provider-visible request schemas, exact preflight wire request/response, request
size, and graph result semantics have not been captured and reviewed. A positive
runtime compatibility claim requires that separate work and an independently
enrolled profile digest; the synthetic unit-test descriptors are not such a
capture. No live model, target, Docker, or Strix process was run for this profile.
The launcher seals both the provider entrypoint and its imported conformance
module in the runtime digest; a changed allowlist or schema policy invalidates
the prepared launch. This file seal is preflight evidence, not proof of the
installed interpreter's import resolution.
