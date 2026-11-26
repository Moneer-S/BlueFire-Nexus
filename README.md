<p align="center">
  <img src="docs/assets/brand/bluefire-mark.svg" alt="" width="46" height="54">
</p>

<h1 align="center">BlueFire Nexus</h1>

<p align="center"><strong>Watch an attack move through a real network, step by step, next to what its defenses saw.</strong><br>
Each step is drawn on a map and marked alerted, seen (recorded, no alert) or unseen (not recorded).</p>

![The live view playing a recorded attack path on a map of seven hosts. It opens at the end of the path, every hop drawn and the goal marked reached, then plays the password guessing until Wazuh alerts, the login to the build server until it is told seen with no alert, and the upload to the goal again](docs/assets/front/live-view-loop.gif)

<p align="center">Wazuh, an open-source security monitor, alerted on the password guessing on the web server a minute in. About eleven minutes later the build server's signing secret was copied to inet, the stand-in internet, with no alert.</p>

## Open the recording

Download [`docs/live-view/attack-path.html`](docs/live-view/attack-path.html) and open it in a browser; it holds this recording and works offline.

Or run `docker compose up app`, open the address it prints, and choose **Runs** in the menu, then the attack path: the app replays the recorded runs and attacks nothing on your machine. With Docker Desktop, switch on "Enable host networking" in its settings first.

The network is seven containers built from one spec file, on networks with no route out, and it was recorded on a GitHub-hosted runner. Each step runs a test from Atomic Red Team, a public library of attack tests. [How the network is built and run](lab/README.md#range-one-its-hosts) names each host and gives the command that runs the path in Docker.

## What you can do with it

### Read what no rule alerted on

Every step after the password guessing was recorded, and no rule alerted on any of them. In the recording, drag the timeline to step 9, pictured: every stock rule that matched it was below alert level, and the screen names the one to start from.

![The live view late in the step that logs in to the build server with the key it found and copies files back: the hop from the web server to the build server lit, the step told seen with two rules matched for review and none at alert level, Fix this beside it, and a hint to start from the rule "Integrity checksum changed"](docs/assets/front/path-no-alert.png)

### Change a defense, see before and after

On the Runs screen, **Before against after** holds two changes to a Linux machine's defense: new auditd settings took "Clear Bash history (echo)" from unseen to seen, then a rule written by hand from its event alerted on 4 steps that were seen. The score counts published rules only, so it still marks those 4 steps seen.

![The two changes on the Runs screen, in the order they were made: new auditd settings, after which Clear Bash history (echo) went from unseen to seen, then a new rule, after which 4 steps went from seen to alerted with the lab's rules](docs/assets/front/app-runs-pair.png)

### Find what nobody saw

On the Runs screen, open the run on one Linux machine and press **Analyse**: the table lists first the one unseen test, "Clear Bash history (echo)". Click it: the panel beside the table says what happened and where to start.

![The app's Analyse screen of the run on one Linux machine: the table of all 91 steps with the unseen test, Clear Bash history (echo), first and chosen, and beside the table its detail, which says it took effect and nothing of the test was recorded besides its launcher's start, with Fix this and the advice to start with a sensor](docs/assets/front/app-analyse.png)

### See what hardening stopped

Some of those tests ran a second time on a hardened machine. In **Analyse**, the **Hardened** tab lists these reruns, each marked stopped or not; **Watch from here** on one shows it with the hardening change named, next to what the same test did without it.

![The app's live view of the run on one Linux machine, opened from the Hardened tab with Watch from here and paused late in a rerun: the host's badge and the step both say stopped, the hardening change is named under the step, and under that the same test without the change took effect and was seen with no alert](docs/assets/front/app-watch-stopped.png)

---

<p align="center"><a href="docs/README.md">Documentation</a> · <a href="docs/WORKSPACE.md">The full tour</a> · <a href="docs/INSTALLATION.md">Install</a> · <a href="lab/README.md">How the runs are made</a> · <a href="docs/SCOPE.md">Scope</a> · <a href="LICENSE">License</a></p>
