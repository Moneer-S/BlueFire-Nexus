"""BlueFire-Nexus test suite.

Marks `tests/` as a package so cross-test helper imports work from a clean
`pip install -e .` install (e.g. CI), not just from the project root via
pytest's rootdir injection.
"""
