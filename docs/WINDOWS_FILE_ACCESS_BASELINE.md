# Windows Paired Readable Baseline

This development workflow creates a disposable local Windows reader and generated file, records a reviewed paired-read baseline, and can then perform one separately reviewed metadata-only access correction with a fresh paired retest. It is local file-access work, not an Active Directory, SMB, cloud, or production-host workflow. Setup does not delete the local account or generated resource; arrange authorized cleanup before starting.

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

A completed baseline requires both the owner and non-owner to read the generated file successfully with matching content. It records those bounded reads and native and owned-job cleanup observations. The record is runner-reported evidence, not independent telemetry or general filesystem authorization, and says nothing about other files or hosts.

## Review the access correction

After a settled paired baseline, continue only if the saved Windows control offers **Review Windows access change**. Review that exact operation separately. It changes only the enrolled generated file's protected DACL to metadata-only access for the non-owner, then performs a fresh paired retest: non-owner data access must be denied while the owner can still read unchanged content. The correction is bound to the original setup, baseline, resource generation, and descriptor preimage; it does not renew setup or operation expiry.

The correction is source-integrated, but installed Windows operation and live native proof remain pending. A successful local or synthetic check is not evidence that this change is ready or effective on a live host. Do not broaden the target, change other ACLs, or treat process closure as proof of access policy.

## If the result is uncertain

Do not resubmit a baseline or correction to recover an uncertain attempt. Use **Review original task evidence** for that exact saved operation and inspect or reconcile its original result. Recovery does not repeat the read, correction, or retest, and does not extend the original deadline. If the outcome or cleanup remains unresolved, preserve the original host and protected state for authorized follow-up; do not infer success or start a replacement operation.

## Cleanup remains required

The workflow provides no general rollback or account/resource deletion action. The generated local reader and file remain a cleanup obligation after baseline, correction, or retest. Arrange a separately reviewed and authorized cleanup procedure before setup. Do not claim the correction was reversed or resources removed; do not infer cleanup from a closed child process, a closed UI session, a successful result, or an imported setup record.

## Evidence boundary

The protected setup receipt records setup provenance; it does not claim that paired reads occurred. Baseline, correction, and retest records are runner-reported and their closure observations are not independent telemetry or broad security-effectiveness evidence. Synthetic tests and browser fixtures verify software behavior only. Installed Windows operation and native live proof remain pending; this guide does not claim a completed live validation or supported-release workflow.
