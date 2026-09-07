# Run a saved experiment with Assistant

After reviewing and saving an Assistant graph proposal, choose **Run with Assistant** from its saved result or Builder review. Runs opens that exact saved version in a separate setup view. Your current Builder draft stays available.

1. Choose **Simulate** or **Execute**, the runner profile, target scope, and observations. These settings apply to the saved experiment shown beside them. They remain available when you return to this setup in the same browser session.
2. Set **AI during the run** if you want the runtime planner to review or choose allowed methods. **Off** uses deterministic runtime planning. This is separate from the Assistant that prepares the run and reviews its evidence.
3. Choose **Run with Assistant**. Select the **Assistant mode** and **Assistant provider**, then describe the work: for example, “Run this version using these settings, then explain its observations and cleanup.” The provider and settings are explicit; the model cannot supply a different target scope or grant execution approval.
4. In **Assist**, open the run review. Inspect the complete plan, including branches, scope, cleanup, and any findings. Accepting submits the selected run request. In **Auto**, supported preparation work can continue under the settings you selected.
5. **Execute always needs the ordinary fresh job approval.** Open the linked job to review its authorization and follow progress. Runtime AI may also require its own proposal review. Closing the Assistant does not stop saved work.
6. Return to Assistant or the run preparation to inspect the result. The evidence review distinguishes independently observed records from simulated or runner-reported records. A simulation or missing observations cannot establish that a real action or defense worked. Open the run record to inspect evidence, cleanup, and exports.

The saved graph's original result continues to say **Not run** because it records what saving accomplished. Later execution and evidence review have their own run records; they do not rewrite that original receipt.

## Returning after an interruption

The Assistant retains its submitted graph version, settings, provider, and request. A directly linked run preparation can reopen its original Assistant operation from the local service. If another saved operation is already open, check or settle that operation before opening a different one.

A run-review decision is retained before submission. If its response is lost, **Retry acceptance** or **Retry decline** checks that same decision. Reload does not create another decision or authorize an additional execution. A failed or uncertain run is never automatically repeated. Use the saved operation's recovery guidance; recovering evidence inspection keeps the same recorded run.

Use **Stop this operation** in Assistant to request cancellation and prevent further work. Keep the recorded job and cleanup status in view until they confirm the outcome. A stop request is not proof of termination, and closing a browser panel is not cancellation.

## Scope of evidence review

This workflow uses the existing run controller, approvals, collector records, and saved bundles. The model receives bounded evidence context and must refer to that run's available evidence. Missing observations, incomplete cleanup, and simulated results remain explicit limitations. An explanation of evidence is not a validated detector, a prevention result, or a substitute for independent benign and held-out evaluation.
