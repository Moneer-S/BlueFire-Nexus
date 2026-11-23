# The live view

The live view plays a recording (see [RECORDING.md](RECORDING.md)) on a map of
its network: each step of the attacker in plain words, what the sensors
recorded, which rules matched, the clock, and the score. It opens in two
places: inside the app, where the Runs screen plays a recorded run (see the
[user guide](USER_GUIDE.md#recorded-runs)), and as the single replay page: one
HTML file that holds the view and one recording, and plays in a browser with
nothing installed. A recording whose run is still going plays as far as it
goes, and the view says the run is still running.

## What it shows, and what it never shows

- **Only what the recording holds.** Every step, event, match, time and number
  on screen comes from the recording. A value the recording leaves out is shown
  as not known; nothing is estimated, filled in or made up.
- **A match is not an alert.** An alert is a match of a published rule at level
  `high` or `critical` on an event of the step. A match below that level is
  shown for review, and a match on the shell command that carried the test only
  is shown as a launcher match. Neither counts.
- **Rules written in this repository are drawn apart and not scored.** Their
  matches are labelled "not scored" or "would alert", and the score never
  counts them.
- **Silences are shortened, and the screen says so.** Every step gets one bar
  on the timeline, and the time between two steps plays as a short beat
  whatever its real length. The legend under the timeline says "silences
  shortened", and the clock always shows the recording's own time. A step whose
  last match fires near its end stays on screen, its clock held at the step's
  end, until that match's light has reached the rule engine and the step's
  outcome is told.
- **The score is the recording's.** While watching, the score counts a step
  once the screen has told its outcome; at the end of the run it is the
  recording's `score`. False alerts, on ordinary activity outside every step,
  have no times in a recording, so watch mode shows them only at the end. In
  analyse mode it is the whole run's score from the start.

## Two modes

- **Watch** plays the run. The caption tells the current step in plain words,
  then its outcome: alerted, seen with no alert, unseen, stopped. A step that
  got through without an alert has a "Fix this" button: it opens the step's
  detail, which says where the gap is. Inside the app a note above the view
  also says that BlueFire cannot make the change yet.
- **Analyse** shows the whole run on one axis, the table of every step with
  filters by role and outcome, and the chosen step's detail: how it went, its
  times, the command, the rules that matched and its events. "Watch from here"
  goes back to watch mode at that step.

## Keys

| Where | Key | Does |
| --- | --- | --- |
| Watch mode | Space | Plays or pauses, unless a button, link or the timeline has focus |
| Timeline | Left, Right (or Down, Up) | One step back or on |
| Timeline | Shift with an arrow | One second back or on |
| Timeline | Page Down, Page Up | Ten steps back or on |
| Timeline | Home, End | The start or the end of the run |
| Analyse: the lanes | Left, Right, Home, End | Moves between steps |
| Analyse: the table | Up, Down, Home, End | Moves between rows |
| Tool versions | Escape | Closes the panel |

## The page's address

The replay page reads where to start from its address, for example
`replay.html?step=43&paused=1`:

| Parameter | Value | Does |
| --- | --- | --- |
| `step` | a step's `id` | Opens at that step |
| `at` | 0 to 1 | How far into that step; 0.6 when left out. Read only with `step`. |
| `paused` | `1` | Opens paused |
| `mode` | `watch` or `analyse` | Opens in that mode; analyse opens paused |
| `select` | a step's `id` | The step whose detail analyse mode opens on |

## Making the page

```bash
bluefire recordings page RECORDING_ID --out replay.html
```

The command writes a new file: the packaged page `bluefire/ui/replay.html`
with the recording put inside it (see [CLI.md](CLI.md)). `bluefire recordings
list` gives the ids. A page is made of a finished run: the command refuses a
recording that is still running (it has no end time yet) and writes nothing;
a running recording is watched in the app. The page is one file of under 1 MB
plus the recording.
It carries its own script, styles and font, and its content security policy
lets it load nothing and connect nowhere: the page makes no request by itself.
The one way out is the link to the CI run that made the recording, shown only
for a GitHub Actions run at `https://github.com` (of the recording's own
repository, when the recording names one), and followed only when someone
clicks it. The text of a recording is always shown
as text, never read as markup.

Beside the recording the command writes where it comes from, as the app lists
it, and the page shows that note under the title at all times. A recording
shipped with BlueFire says so and names the CI run that made it. An imported
recording says what BlueFire checked, that the file follows the format and its
parts agree, and what it cannot confirm: that the steps ran, where and when,
and the engine and CI run the file names. A page that holds no such note, a
template filled by other means, says that it does not say where its recording
comes from.

The browser test `frontend/tests/service/replay-page.spec.ts`, run by the app
workflow, makes this page for the shipped recording and checks what a person
does and sees on it: where the recording comes from, for a shipped, an imported
and an unsaid origin, watching, playing and pausing, moving on the timeline by
pointer and keyboard, the address, the unseen test and its fix hint, analyse
mode, the score at the end, and that the page makes no request.
