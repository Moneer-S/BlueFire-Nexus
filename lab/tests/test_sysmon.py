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


def records(*numbers: int) -> list[dict[str, str]]:
    return [{"EventRecordID": str(number)} for number in numbers]


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
