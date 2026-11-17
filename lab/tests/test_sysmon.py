from pathlib import Path

from bluefire_lab import sysmon

# One line as Sysmon for Linux 1.6.0 wrote it on a hosted runner, from the
# sensor spike (workflow run 43803220104). A fixture, not a result.
PROCESS_START = (
    '<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>'
    "<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>"
    '<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-11-16T04:19:43.280911000Z"/>'
    '<EventRecordID>182</EventRecordID><Correlation/><Execution ProcessID="3912" ThreadID="3912"/>'
    "<Channel>Linux-Sysmon/Operational</Channel><Computer>runnervm8axu0</Computer>"
    '<Security UserId="0"/></System><EventData><Data Name="RuleName">-</Data>'
    '<Data Name="UtcTime">2026-11-16 04:19:43.274</Data>'
    '<Data Name="ProcessGuid">{5912aea2-845f-6afa-f125-db9fa5550000}</Data>'
    '<Data Name="ProcessId">4043</Data><Data Name="Image">/usr/bin/uname</Data>'
    '<Data Name="CommandLine">uname -a</Data><Data Name="User">lab</Data>'
    '<Data Name="TerminalSessionId">5</Data>'
    '<Data Name="ParentProcessGuid">{5912aea2-845f-6afa-1d88-e52f30560000}</Data>'
    '<Data Name="ParentProcessId">4041</Data><Data Name="ParentImage">/usr/bin/dash</Data>'
    '<Data Name="ParentCommandLine">sh</Data></EventData></Event>'
)


def test_an_event_line_gives_its_fields() -> None:
    event = sysmon.parse_line(PROCESS_START)

    assert event["EventID"] == sysmon.PROCESS_START
    assert event["EventRecordID"] == "182"
    assert event["CommandLine"] == "uname -a"
    assert event["TerminalSessionId"] == "5"
    assert event["ParentProcessId"] == "4041"


def test_a_line_without_a_whole_event_is_not_an_event() -> None:
    assert sysmon.parse_line("Sysmon v1.6.0 - Monitors system events") is None
    assert sysmon.parse_line(PROCESS_START[:400]) is None


def test_reading_a_file_keeps_events_and_other_lines_apart(tmp_path: Path) -> None:
    path = tmp_path / "sysmon.txt"
    path.write_text(f"Stopping....\n{PROCESS_START}\nLost events: 0, in 0 notifications\n", encoding="utf-8")

    events, raw, other = sysmon.read(path)

    assert [event["EventRecordID"] for event in events] == ["182"]
    assert raw == [PROCESS_START]
    assert other == ["Stopping....", "Lost events: 0, in 0 notifications"]


def test_an_event_whose_text_holds_a_line_break_is_read_as_one(tmp_path: Path) -> None:
    command = "sh -c cp /bin/sh /tmp/crond;\necho 'sleep 5' | /tmp/crond"
    split = PROCESS_START.replace('<Data Name="CommandLine">uname -a', f'<Data Name="CommandLine">{command}')
    path = tmp_path / "sysmon.txt"
    path.write_text(f"{split}\n{PROCESS_START}\n", encoding="utf-8")

    events, raw, other = sysmon.read(path)

    assert [event["CommandLine"] for event in events] == [command, "uname -a"]
    assert other == []
    assert "\n" not in sysmon.one_line(raw[0])
    assert sysmon.parse_line(sysmon.one_line(raw[0]))["CommandLine"] == command


def test_an_event_cut_short_at_the_end_is_not_an_event(tmp_path: Path) -> None:
    path = tmp_path / "sysmon.txt"
    path.write_text(f"{PROCESS_START}\n{PROCESS_START[:300]}\nmore text\n", encoding="utf-8")

    events, _, other = sysmon.read(path)

    assert len(events) == 1
    assert other == [f"{PROCESS_START[:300]}\nmore text"]


def records(*numbers: int) -> list[dict[str, str]]:
    return [{"EventRecordID": str(number), "EventID": sysmon.PROCESS_START} for number in numbers]


def test_loss_counts_how_often_the_sensor_started() -> None:
    started = {"EventRecordID": "1", "EventID": "4", "State": "Started"}
    stopped = {"EventRecordID": "9", "EventID": "4", "State": "Stopped"}

    assert sysmon.loss([started, stopped], [])["sensor_starts"] == 1
    assert sysmon.loss([started, started, stopped], [])["sensor_starts"] == 2


def test_loss_reads_the_sensors_own_count() -> None:
    lines = ["Total events: 507, bad events: 2, ratio = 0.003945", "Lost events: 3, in 1 notifications"]

    lost = sysmon.loss(records(1, 2, 3), lines)

    assert (lost["sensor_reported"], lost["lost_events"], lost["bad_events"]) == (True, 3, 2)
    assert lost["missing_records"] == 0


def test_loss_counts_the_records_missing_from_the_export() -> None:
    lost = sysmon.loss(records(10, 11, 14, 15), ["Lost events: 0, in 0 notifications"])

    assert lost["records"] == 4
    assert lost["missing_records"] == 2


def test_loss_says_when_the_sensor_did_not_report() -> None:
    lost = sysmon.loss(records(1, 2), ["Sysmon v1.6.0 - Monitors system events"])

    assert lost["sensor_reported"] is False
    assert lost["lost_events"] is None


def test_loss_needs_both_counts_once_each() -> None:
    counts = ["Total events: 507, bad events: 0, ratio = 0", "Lost events: 0, in 0 notifications"]

    assert sysmon.loss(records(1, 2), counts)["sensor_reported"] is True
    assert sysmon.loss(records(1, 2), counts[1:])["sensor_reported"] is False
    assert (
        sysmon.loss(records(1, 2), [*counts, "Lost events: 7, in 2 notifications"])["sensor_reported"]
        is False
    )


def test_loss_counts_a_record_number_that_repeats() -> None:
    assert sysmon.loss(records(1, 2, 2, 3), [])["repeated_records"] == 1
    assert sysmon.loss(records(1, 2, 3), [])["repeated_records"] == 0
