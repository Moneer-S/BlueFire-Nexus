<p align="center">
  <img src="docs/assets/brand/bluefire-mark.svg" alt="" width="46" height="54">
</p>

<h1 align="center">BlueFire Nexus</h1>

<p align="center"><strong>Watch attacks that ran on a real machine, step by step, next to what its defenses saw.</strong><br>
For each step you see whether a sensor recorded it and whether a rule raised an alert. Change a defense, run it again, and see the difference.</p>

![The live view playing a recorded run on one Linux machine: a published rule has raised the first alert, the next test takes effect with nothing recorded and is marked unseen, then the alerted test plays from its start, its events travelling through two sensors to the rule engines](docs/assets/front/live-view-loop.gif)

<p align="center">Recorded on a throwaway Linux machine: a published rule raises its first alert, then the next test does its work and neither sensor records it.</p>

## See it in a minute

Download [`docs/live-view/replay.html`](docs/live-view/replay.html) and open it. It plays in any browser, offline, with nothing installed, and you can send it to anyone.

Or run `docker compose up app`, open the address it prints, then **Runs**: the app opens with the recorded runs and attacks nothing on your machine.

## What you can do with it

### Change a defense, see before and after

Change a sensor's settings or a rule in a pull request, and the lab's CI shows what it moved. Here a change to the settings of auditd got the test nobody saw recorded.

![Before against after in the app: one change to the settings of auditd, and the test nobody saw moved from unseen to seen, with the event it now records](docs/assets/front/app-pair.png)

### Find what nobody saw

The same run, all of it, in a table. The test no sensor recorded comes first, and beside it what happened and where to start fixing it.

![Analyse mode: every test of the run in a table with what recorded it and what alerted, the unseen test first and selected, and beside it what happened and where to start](docs/assets/front/analyse-unseen.png)

### See what hardening stopped

Some tests run a second time with one hardening change made. Each shows whether the change stopped it, next to what the same test did without it.

![The live view on a test run again on a hardened machine: marked stopped, with the hardening change named, next to what the same test did without it](docs/assets/front/watch-stopped.png)

---

<p align="center"><a href="docs/OPERATOR_GUIDE.md">Documentation</a> · <a href="docs/WORKSPACE.md">The full tour</a> · <a href="docs/INSTALLATION.md">Install</a> · <a href="lab/README.md">How the runs are made</a> · <a href="docs/SCOPE.md">Scope</a> · <a href="LICENSE">License</a></p>
