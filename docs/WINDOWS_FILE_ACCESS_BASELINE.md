# Windows Paired Readable Baseline

This development workflow creates a disposable local Windows reader and generated file, then records one reviewed comparison of reads by the owner and non-owner. It is create-only: setup and baseline do not delete the local account or generated resource. Arrange authorized cleanup before starting.

## Before you begin

- Use the Windows x86-64 BlueFire package and its matching packaged runner. Choose a current runner profile available on this host.
- Use a disposable Windows host where you are authorized to create the dedicated local reader and generated file. This is local file-access work, not an Active Directory, SMB, cloud, or production-host workflow.
- Run setup as the local owner from an elevated Windows session with its actual linked non-elevated token. Setup verifies that both tokens belong to the same local owner; it does not accept a caller-supplied identity as proof.
- After setup, return to that same owner's non-elevated session for the protected receipt import and File Access workflow. Receipt reading refuses an elevated caller.
- Keep the host and protected BlueFire state available until the original operation and cleanup status are resolved. Closing the browser does not clean up the account or file.
- Setup and review records expire. Saving or reopening a record preserves its original expiry; it does not renew it.

## Create the paired setup

Run the command once, choosing the exact Windows-capable profile prepared for this host:

```powershell
bluefire runner windows-file-baseline-setup --profile PROFILE_ID --confirm-create-local-reader
```

The required confirmation is explicit because setup creates a local reader and generated resource. This command uses BlueFire's fixed managed product state and refuses `--config` and `--runs-dir` overrides. Do not repeat setup to recover an interrupted or uncertain attempt.

Continue only when the result says `publication` is `complete` and `process_cleanup` is `verified`. The result still says `account_object_cleanup` is `required`, `context_available` is false, `native_read_proof` is false, and `settled` is false. These fields are distinct: verified process closure does not remove the account or file, and publishing setup is not a paired read result.

If publication or process cleanup is not established, preserve the original host and protected state. The setup command's cleanup owner exists only for that CLI process; when cleanup is unknown, there is no retained retry handle after the command exits. Do not rerun setup or infer that the account, file, or whole process job was cleaned up.

## Save and review in File Access

In the same owner's non-elevated session, start BlueFire normally and connect using the one-time code from the local UI launcher. In **File Access**, choose **Save verified setup** for the exact current setup. Confirm its reference, digest, and original expiry, then open the saved Windows control.

Choose **Review paired baseline** only when the current control allows it. Review the exact operation and authorize it once. A fresh review is short-lived; if it expires, refresh and review the current record rather than reusing an old approval.

A completed result is a recorded paired baseline for the generated file. It reports the two bounded reads and whether their content matched, along with native and owned-job cleanup observations. The record explicitly says it is not independent telemetry. It is not general filesystem authorization, a hardening test, or evidence about other files or hosts. Other file-access operations remain unavailable in this phase.

## If the result is uncertain

Do not submit another baseline for the same setup. Use **Review original task evidence** for the original saved operation and inspect or reconcile that operation. Reconciliation reads the original task record; it does not dispatch another baseline. If the outcome or cleanup remains unresolved, leave it unresolved and retain the original host and protected state for authorized follow-up.

## Cleanup remains required

This phase provides no account or resource deletion action. The generated local reader and file remain a cleanup obligation even after a successful comparison. Arrange cleanup through a separately reviewed, authorized procedure. Do not infer cleanup from a closed child process, a closed UI session, a successful baseline, or an imported setup record.

## Evidence boundary

The protected setup receipt records setup provenance; it does not claim that paired reads occurred. A baseline operation records the runner-reported read result and closure observations; it does not claim independent observation or broad security effectiveness. Synthetic tests and browser fixtures verify software behavior only. Installed Windows operation and native live proof remain pending; this guide does not claim a completed live validation or supported-release workflow.
