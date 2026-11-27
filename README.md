<p align="center">
  <img src="docs/assets/brand/bluefire-mark.svg" alt="" width="46" height="54">
</p>

<h1 align="center">BlueFire Nexus</h1>

<p align="center"><strong>The attacker reached its goal; none of the 5 defenses stopped it.</strong><br>
Watch the same real run through each defense, step by step, beside what it saw, alerted on and missed.</p>

![The live view playing a recorded attack path on a map of seven hosts. It opens at the completed path with the goal reached and five defense judgments available, then plays the password guessing until stock Wazuh alerts, the login to the build server until it is told seen with no alert, and the upload to the goal again](docs/assets/front/live-view-loop.gif)

<p align="center">Stock Wazuh alerted on the password guessing; a tuned correlation alerted near the goal. Public Sigma, ET Open and the combined AI-tool packs raised no counting alert. Every defense let the signing secret reach inet.</p>

## Open the recording

Download [`docs/live-view/attack-path.html`](docs/live-view/attack-path.html) and open it in a browser; it holds this recording and works offline.

Or run `docker compose up app`, open the address it prints, and choose **Runs** in the menu, then the attack path: the app replays the recorded runs and attacks nothing on your machine. With Docker Desktop, switch on "Enable host networking" in its settings first.

The network is seven containers built from one spec file, on networks with no route out, and it was recorded on a GitHub-hosted runner. Each step runs a test from Atomic Red Team, a public library of attack tests. [How the network is built and run](lab/README.md#range-one-its-hosts) names each host and gives the command that runs the path in Docker.

## What you can do with it

### Compare 5 defenses on the same run

Use **Judged by** beside the map to switch between stock Wazuh, public Sigma, ET Open, the combined AI-tool packs and the tuned ordered rule. Press **Analyse** to compare their completed results. Wazuh and the tuned rule alerted; the other 3 did not. None stopped the attacker, and none raised a false alert on the ordinary activity in this run.

![The completed attack path at its goal: all seven hosts and every hop on the map, the signing secret marked as reached, and five named defenses beside it with their completed alerted, seen, unseen and false-alert counts](docs/assets/screenshots/live-view-path-goal.png)

### Change a defense, see before and after

On the Runs screen, **Before against after** holds two changes to a Linux machine's defense: new auditd settings took "Clear Bash history (echo)" from unseen to seen, then a rule written by hand from its event alerted on 4 steps that were seen. The score counts published rules only, so it still marks those 4 steps seen.

![The two changes on the Runs screen, in the order they were made: new auditd settings, after which Clear Bash history (echo) went from unseen to seen, then a new rule, after which 4 steps went from seen to alerted with the lab's rules](docs/assets/front/app-runs-pair.png)

### Find what nobody saw

On the Runs screen, open the run on one Linux machine and press **Analyse**: the table lists first the one unseen test, "Clear Bash history (echo)". Click it: the panel beside the table says what happened and where to start.

![The app's Analyse screen of the run on one Linux machine: the table of the 60 tests with the unseen test, Clear Bash history (echo), first and chosen, and beside the table its detail, which says it took effect and nothing of the test was recorded besides its launcher's start, with Fix this and the advice to start with a sensor](docs/assets/front/app-analyse.png)

### See what hardening stopped

Some of those tests ran a second time on a hardened machine. In **Analyse**, the **Hardened** tab lists these reruns, each marked stopped or not; **Watch from here** on one shows it with the hardening change named, next to what the same test did without it.

![The app's live view of the run on one Linux machine, opened from the Hardened tab with Watch from here and paused late in a rerun: the host's badge and the step both say stopped, the hardening change is named under the step, and under that the same test without the change took effect and was seen with no alert](docs/assets/front/app-watch-stopped.png)

---

<p align="center"><a href="docs/README.md">Documentation</a> · <a href="docs/WORKSPACE.md">The full tour</a> · <a href="docs/INSTALLATION.md">Install</a> · <a href="lab/README.md">How the runs are made</a> · <a href="docs/SCOPE.md">Scope</a> · <a href="LICENSE">License</a></p>
