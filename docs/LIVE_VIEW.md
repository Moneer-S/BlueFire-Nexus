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
- **A step plays its own stretch of the run, unmoved.** A step's bar plays
  from its `started`, or its earliest event or match when a sensor stamped one
  a moment before, to its `ended`, or its latest event or match. The format
  has steps run forward with no overlap and no step's events inside another's
  stretch, and the page refuses a file that breaks that, so no step is moved or
  squeezed to fit, and the clock, the log, the analyse lanes and a step's
  detail read the same times. "The step ended", wherever it is said or
  counted, is the step's recorded `ended` (the end of its stretch when the
  recording has none).
- **A match fires at its moment.** Its moment is its `raised` time where the
  rules ran live and its `time` where they ran after the run, the moment the
  recording's `first_alert` and `first_alert_seconds` count. It fires then, as
  soon as the earliest event it names has arrived; it does not wait for later
  events it names, which arrive after it as events of a match already told.
- **An alert raised after its step ended arrives late, and is shown when it
  arrives.** Where the rules ran live, a match fires at its `raised` time.
  While a step is on screen it is told as it stood at its end, so a step whose
  alert was not raised yet is told as seen (or unseen) with no alert by the end
  of the step. When a match of a step is raised after that step ended, on
  whatever is on screen then (a later step, or the silence after its own
  step), its rule engine lights, the log gets a line marked "raised late", and
  one line under the step names it and says how long after its step ended it
  was raised. When several arrive together, that line counts and names every
  one of them, the log names the earlier ones on a line of their own, and each
  engine says how many more arrived on it, so nothing that the score counts
  goes unnamed. A match raised after its step's `ended` that still fires while
  that step's own stretch plays (a sensor stamped one of its events later
  still) is late in the same way, and the step waits for it: it is told
  alerted when that match fires, never first as seen. What is on screen
  holds, its clock and the race's head stopped at that arrival's moment, until
  that line has been there for three seconds; the rest of the silence then
  plays. From that moment the score, the race line and
  that step's bar on the timeline count it as alerted, and not before; when it
  fires in the silence after its own step, while that step is still on screen,
  the step's verdict and its host's badge say alerted from then too, and its
  sentence still says there was no alert by the end of the step. A match
  raised after the last step ended plays in one more short silence at the end.
  In analyse mode each such match says how long after its step ended it was
  raised. Where a step has several alerts, the caption, the first alert's flag
  and the step's detail all name the one that fired first on screen (by its
  `raised` time where the rules ran live), not the one whose event came first,
  and a rule is named only once its alert has fired. The same holds for every
  match, at any level: the caption's count of rules for review, its "Fix this"
  hint, its text for screen readers and a rule engine's "no rule matched" speak
  only of the matches that have fired by then, and a match that fires later
  appears when it fires. Analyse mode shows the whole run at once and lists a
  step's matches in firing order.
- **The score is the recording's.** While watching, the score counts a step
  once the screen has told its outcome; at the end of the run it is the
  recording's `score`. False alerts, on ordinary activity outside every step,
  have no times in a recording, so watch mode shows them only at the end. In
  analyse mode it is the whole run's score from the start. False alerts are
  shown only with the ordinary activity they are counted from. The time to the
  first alert, wherever it is shown, is read from the alerts themselves: from
  the first test's start to the moment that alert fires (its `raised` time
  where the rules ran live), the same clock the race compares with the goal.
  An attack path begins with a test that has a recorded start, and its race
  counts from that one moment: the first alert's number, the goal, the race
  track's 00:00, the flags' places on it and the clock's time into the run.
  The goal falls `score.goal_seconds` after it, even where an event is stamped
  before that start, and the race line and the run's summary name the
  attacker's goal where they say it was reached. When the first alert came
  before the goal, the race line tells the goal only once that alert has been
  told, never the other way round. A file whose `score.first_alert_seconds`,
  or a step's `first_alert`, says otherwise is refused on import; the page
  shows what the alerts say.

## Two modes

- **Watch** plays the run. The caption tells the current step in plain words,
  then its outcome: alerted, seen with no alert, unseen, stopped. A step that
  got through without an alert has a "Fix this" button: it opens the step's
  detail, which says where the gap is. Inside the app a note above the view
  also says that BlueFire cannot make the change yet.
- **Analyse** shows the whole run on one axis, the table of every step with
  filters by role and outcome, and the chosen step's detail: how it went, its
  times, the command, the rules that matched and its events. "Watch from here"
  goes back to watch mode at that step. The table opens on the tests, or on
  every step when the recording has no test.

In a small window, or a large one zoomed in, the view grows with what it
holds and the page scrolls; at phone width its bands stack. Nothing is cut
off beyond reach. The app's page of a recorded run does the same at the same
window sizes.

## Keys

| Where | Key | Does |
| --- | --- | --- |
| Watch mode | Space | Plays or pauses, unless a button, link or the timeline has focus |
| Timeline | Left, Right (or Down, Up) | One step back or on; on the last step, on goes to the end |
| Timeline | Shift with an arrow | One second back or on |
| Timeline | Page Down, Page Up | Ten steps back or on; on never goes back |
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
| `at` | 0 to 2 | How far into that step, 0 its start and 1 its end. Above 1 and below 2, how far into the silence after it, where that step is still on screen; 2 or more is that silence's end, which is the next step's start. On the last step, which has no silence after it, anything above 1 is its end. 0.6 when left out. Read only with `step`. |
| `paused` | `1` | Opens paused |
| `mode` | `watch` or `analyse` | Opens in that mode; analyse opens paused |
| `select` | a step's `id` | The step whose detail analyse mode opens on |

An address that names a step the recording does not hold gets one line under
the title that says so, in both modes; the view then opens at the start of the
run, or analyse mode on the whole run.

Inside the app, at `#/runs/recorded/<id>`, the same parameters follow the
viewer. A place in a silence counts the silence as it plays, its hold at a
late arrival included, and is written in thousandths rounded up, so the
address opens the same moment with the same late arrivals on screen. An
address that names a step the recording does not hold keeps naming it, beside
the line that says so, until the viewer moves from where the view opened.

## Making the page

```bash
bluefire recordings page RECORDING_ID --out replay.html
```

The command writes a new file: the packaged page `bluefire/ui/replay.html`
with the recording put inside it (see [CLI.md](CLI.md)). `bluefire recordings
list` gives the ids. A page is made of a finished run: the command refuses a
recording that is still running (it has no end time yet) and writes nothing;
a running recording is watched in the app. Every finished recording the app
keeps plays on the page: the import refuses, with a plain reason, anything the
page could not show. The browser test
`frontend/tests/service/recording-parity.spec.ts` gives a small set of
recordings at the edges of the format to both, and checks that the page plays
each one the app keeps and refuses each one it refuses. The page is one file of
under 1 MB plus the recording.
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

Every run of the lab leaves a page of its own: the lab workflow fills the same
template with the run's `recording.json` (`bluefire-lab replay`, see
[lab/README.md](../lab/README.md)), and that page says it was made by the lab
workflow in the CI run it names. The same command run anywhere else writes a
page that says only which CI run recorded the recording.

## Pictures made in CI

The pictures of the live view are made in CI, on a clean runner, never on a
developer's machine. After its browser tests, the job `screens in a browser`
of the app workflow (`.github/workflows/app.yml`) runs
`frontend/tests/pictures/live-view.ts` against the real service and the
shipped recording. It makes the replay page with `bluefire recordings page`
and takes pictures of it, paused at moments it finds by the steps' outcomes:
the first alert on a test, the unseen test, a test seen with no alert, a
hardened rerun that was stopped, analyse mode with the whole run and with the
unseen test's detail, and the first alert again at 1920 by 1080. Inside the app
it takes the Runs screen and the recorded run's page on the first alert, at
1920 by 1080 so that every rule title fits. It fails if a page prints an error,
if the replay page asks for anything beyond its own file or the app for
anything beyond the service, or if a picture would show a rule title cut short.

The run keeps them for 90 days as the artifact `live-view-pictures`: the
pictures, the page `replay.html` they show, and `SOURCE.txt`, which names the
recording, the CI run that recorded it and the commit the pictures were made
from.

The picture of the live view in the [README](../README.md)
(`docs/assets/screenshots/live-view-first-alert.png`) and the page
[`docs/live-view/replay.html`](live-view/replay.html) are files of that
artifact, copied in unchanged; `docs/assets/screenshots/live-view-source.txt`
names the run that made them and the recording they show. To renew them, take
the artifact `live-view-pictures` of a run of the app workflow on `main`, copy
the files over the committed ones byte for byte, and update that note from the
artifact's `SOURCE.txt`. The page holds the recording, so when the recording
changes, the page's entries in `.secrets.baseline` change with those of the
recording.

The browser test `frontend/tests/service/replay-page.spec.ts`, run by the app
workflow, makes this page for the shipped recording and checks what a person
does and sees on it: where the recording comes from, for a shipped, an imported
and an unsaid origin, watching, playing and pausing, moving on the timeline by
pointer and keyboard, the address, the unseen test and its fix hint, analyse
mode, the score at the end, and that the page makes no request.
