"""The stand-in internet's server, run in this process on loopback ports."""

import hashlib
import http.client
import shutil
import ssl
import subprocess
from pathlib import Path

import pytest

from bluefire_lab.range import inet_server


@pytest.fixture
def server(tmp_path: Path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl makes the test certificate")
    tree = tmp_path / "www"
    (tree / "atomics" / "T1105" / "src").mkdir(parents=True)
    (tree / "atomics" / "T1105" / "src" / "atomic.sh").write_bytes(b"echo served\n")
    (tmp_path / "uploads").mkdir()
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=inet",
         "-keyout", str(tmp_path / "key"), "-out", str(tmp_path / "cert")],
        check=True, capture_output=True,
    )  # fmt: skip
    servers = inet_server.serve(
        tree,
        tmp_path / "uploads",
        tmp_path / "access.log",
        tmp_path / "cert",
        tmp_path / "key",
        (0, 0),
        "127.0.0.1",
    )
    yield tmp_path, [s.server_address[1] for s in servers]
    for running in servers:
        running.shutdown()
        running.server_close()


def get(port: int, path: str, secure: bool = False) -> tuple[int, bytes]:
    if secure:
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=ssl._create_unverified_context())
    else:
        connection = http.client.HTTPConnection("127.0.0.1", port)
    connection.request("GET", path)
    response = connection.getresponse()
    return response.status, response.read()


def test_it_serves_a_file_of_its_tree_over_http_and_https(server) -> None:
    _, (plain, secure) = server

    assert get(plain, "/atomics/T1105/src/atomic.sh") == (200, b"echo served\n")
    assert get(secure, "/atomics/T1105/src/atomic.sh", secure=True) == (200, b"echo served\n")
    assert get(plain, "/")[0] == 200
    assert get(plain, "/missing")[0] == 404
    assert get(plain, "/atomics/../../access.log")[0] == 404


def test_an_upload_is_stored_with_its_sha256_in_the_index(server) -> None:
    folder, (_, secure) = server
    body = b"some bytes to store\n"

    connection = http.client.HTTPSConnection("127.0.0.1", secure, context=ssl._create_unverified_context())
    connection.request("POST", "/upload", body=body)
    response = connection.getresponse()

    assert (response.status, response.read()) == (200, b"stored 1\n")
    assert (folder / "uploads" / "1.bin").read_bytes() == body
    assert (folder / "uploads" / "index.tsv").read_text() == (
        f"1 127.0.0.1 {hashlib.sha256(body).hexdigest()} {len(body)}\n"
    )


def test_every_request_gets_one_line_in_the_access_log(server) -> None:
    folder, (plain, secure) = server

    get(plain, "/atomics/T1105/src/atomic.sh")
    get(secure, "/missing", secure=True)

    lines = (folder / "access.log").read_text().splitlines()
    assert [line.rsplit(" ", 1)[0] for line in lines] == [
        "127.0.0.1 GET /atomics/T1105/src/atomic.sh 200",
        "127.0.0.1 GET /missing 404",
    ]
    assert all(float(line.rsplit(" ", 1)[1]) > 0 for line in lines)
