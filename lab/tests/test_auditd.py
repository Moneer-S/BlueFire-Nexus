"""The auditd reader, on lines in the shape auditd 3.1.2 wrote them on a hosted
runner in the sensor spike (workflow run 43803220104). Fixtures, not results."""

from pathlib import Path

from bluefire_lab import auditd

GS = "\x1d"  # the group separator before the interpreted fields
LINES = [
    "type=SYSCALL msg=audit(1794802702.086:178): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c "
    'items=2 ppid=2924 pid=2940 auid=1001 uid=1001 gid=1001 euid=1001 tty=(none) ses=11 comm="sh" '
    f'exe="/usr/bin/dash" subj=unconfined key="shell-start"{GS}ARCH=x86_64 SYSCALL=openat AUID="bluefire-lab" '
    'UID="bluefire-lab"',
    'type=CWD msg=audit(1794802702.086:178): cwd="/home/bluefire-lab"',
    'type=PATH msg=audit(1794802702.086:178): item=0 name="/home/bluefire-lab/" inode=2 dev=fc:00 '
    f'mode=040750 ouid=1001 ogid=1001 nametype=PARENT{GS}OUID="bluefire-lab"',
    'type=PATH msg=audit(1794802702.086:178): item=1 name="/home/bluefire-lab/.bashrc" inode=3 dev=fc:00 '
    f'mode=0100644 ouid=1001 ogid=1001 nametype=NORMAL{GS}OUID="bluefire-lab"',
    # sh -c "echo hi >> ~/.bashrc", hex with a NUL between the arguments
    "type=PROCTITLE msg=audit(1794802702.086:178): proctitle=7368002D63006563686F206869",
    "type=DAEMON_END msg=audit(1794802710.5:0): op=terminate auid=0 res=success",
    "",
]


def test_records_keep_their_order_and_their_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.txt"
    path.write_bytes("\n".join(LINES).encode())

    records = auditd.read(path)

    assert [record["type"] for record in records] == [
        "SYSCALL",
        "CWD",
        "PATH",
        "PATH",
        "PROCTITLE",
        "DAEMON_END",
    ]
    assert records[0]["line"] == LINES[0]
    assert records[0]["time"] == "2026-11-16 04:18:22.086"
    assert records[5]["time"] == "2026-11-16 04:18:30.500"
    assert records[0]["fields"]["ses"] == "11"
    assert records[0]["fields"]["key"] == "shell-start"
    assert records[0]["interpreted"]["SYSCALL"] == "openat"


def test_an_event_joins_its_records_by_serial(tmp_path: Path) -> None:
    path = tmp_path / "audit.txt"
    path.write_bytes("\n".join(LINES).encode())

    event = auditd.events(auditd.read(path))[0]

    assert (event["event"], event["serial"]) == ("1794802702.086:178", "178")
    assert event["call"]["exe"] == "/usr/bin/dash"
    assert event["names"]["AUID"] == "bluefire-lab"
    assert event["paths"] == ["/home/bluefire-lab/.bashrc"]  # the parent folder is left out
    assert event["command"] == "sh -c echo hi"


def test_records_of_different_times_are_different_events_even_with_one_serial(tmp_path: Path) -> None:
    # The daemon numbers its own records apart from the kernel, so a serial can come twice.
    daemon = "type=DAEMON_START msg=audit(1794802600.100:178): op=start ver=3.1.2 auid=4294967295 res=success"
    path = tmp_path / "audit.txt"
    path.write_bytes("\n".join([daemon, *LINES]).encode())

    events = auditd.events(auditd.read(path))

    assert [(event["event"], event["types"][0]) for event in events if event["serial"] == "178"] == [
        ("1794802600.100:178", "DAEMON_START"),
        ("1794802702.086:178", "SYSCALL"),
    ]


def test_a_record_a_program_writes_itself_gives_its_event_process_and_session(tmp_path: Path) -> None:
    # As useradd wrote it in workflow run 44029759448, line 1450 of audit.txt.
    line = (
        "type=ADD_USER msg=audit(1794896298.363:1340): pid=5154 uid=0 auid=0 ses=50 subj=unconfined "
        "msg='op=adding user id=999 exe=\"/usr/sbin/useradd\" hostname=? addr=? terminal=? res=success'"
        f'{GS}UID="root" AUID="root" ID="unknown(999)"'
    )
    path = tmp_path / "audit.txt"
    path.write_bytes(line.encode())

    call = auditd.events(auditd.read(path))[0]["call"]

    assert (call["pid"], call["ses"], call["exe"]) == ("5154", "50", "/usr/sbin/useradd")
    # Its own fields are read from inside msg='...', the first and the last of them whole.
    assert (call["op"], call["id"], call["res"]) == ("adding user", "999", "success")


def test_the_status_auditctl_prints_is_read_by_name() -> None:
    text = "enabled 1\nfailure 1\npid 2831\nlost 0\nbacklog 0\nloginuid_immutable 0 unlocked\n"

    status = auditd.status(text)

    assert (status["enabled"], status["lost"], status["loginuid_immutable"]) == ("1", "0", "0 unlocked")
