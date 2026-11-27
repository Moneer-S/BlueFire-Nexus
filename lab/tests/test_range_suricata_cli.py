from pathlib import Path

from bluefire_lab import __main__ as cli

IMAGE = "registry.example/suricata:8.0.8@sha256:" + "a" * 64


def test_range_score_forwards_both_engines_and_the_defense_spec(monkeypatch, tmp_path: Path) -> None:
    called = {}

    def rescore(
        folder: Path,
        rule_engine: Path | None = None,
        defenses: Path | None = None,
        *,
        suricata_image: str | None = None,
    ) -> int:
        called.update(
            folder=folder,
            rule_engine=rule_engine,
            defenses=defenses,
            suricata_image=suricata_image,
        )
        return 37

    monkeypatch.setattr(cli.range_engine, "rescore", rescore)
    run = tmp_path / "run"
    engine = tmp_path / "zircolite"
    defenses = tmp_path / "defenses.yaml"

    assert (
        cli.main(
            [
                "range",
                "score",
                str(run),
                "--engine",
                str(engine),
                "--defenses",
                str(defenses),
                "--suricata-image",
                IMAGE,
            ]
        )
        == 37
    )
    assert called == {
        "folder": run,
        "rule_engine": engine,
        "defenses": defenses,
        "suricata_image": IMAGE,
    }


def test_range_score_does_not_invent_a_suricata_image(monkeypatch, tmp_path: Path) -> None:
    called = {}

    def rescore(folder: Path, rule_engine=None, defenses=None, *, suricata_image=None) -> int:
        called.update(
            folder=folder,
            rule_engine=rule_engine,
            defenses=defenses,
            suricata_image=suricata_image,
        )
        return 0

    monkeypatch.setattr(cli.range_engine, "rescore", rescore)
    run = tmp_path / "run"

    assert cli.main(["range", "score", str(run)]) == 0
    assert called == {
        "folder": run,
        "rule_engine": None,
        "defenses": None,
        "suricata_image": None,
    }


def test_range_run_forwards_both_post_run_engines(monkeypatch, tmp_path: Path) -> None:
    called = {}

    def run(
        spec: Path,
        out: Path,
        plant=None,
        hold: float = 0,
        rule_engine: Path | None = None,
        *,
        suricata_image: str | None = None,
    ) -> int:
        called.update(
            spec=spec,
            out=out,
            plant=plant,
            hold=hold,
            rule_engine=rule_engine,
            suricata_image=suricata_image,
        )
        return 4

    monkeypatch.setattr(cli.range_engine, "run", run)
    spec = tmp_path / "range.yaml"
    out = tmp_path / "run"
    engine = tmp_path / "zircolite"

    assert (
        cli.main(
            [
                "range",
                "run",
                str(spec),
                "--out",
                str(out),
                "--hold",
                "2.5",
                "--engine",
                str(engine),
                "--suricata-image",
                IMAGE,
            ]
        )
        == 4
    )
    assert called == {
        "spec": spec,
        "out": out,
        "plant": None,
        "hold": 2.5,
        "rule_engine": engine,
        "suricata_image": IMAGE,
    }


def test_range_run_does_not_invent_a_suricata_image(monkeypatch, tmp_path: Path) -> None:
    called = {}

    def run(spec: Path, out: Path, plant=None, hold=0, rule_engine=None, *, suricata_image=None) -> int:
        called.update(
            spec=spec,
            out=out,
            plant=plant,
            hold=hold,
            rule_engine=rule_engine,
            suricata_image=suricata_image,
        )
        return 0

    monkeypatch.setattr(cli.range_engine, "run", run)
    spec = tmp_path / "range.yaml"
    out = tmp_path / "run"

    assert cli.main(["range", "run", str(spec), "--out", str(out)]) == 0
    assert called == {
        "spec": spec,
        "out": out,
        "plant": None,
        "hold": 0,
        "rule_engine": None,
        "suricata_image": None,
    }
