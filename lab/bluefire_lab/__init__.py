"""A test bench for defenders.

It runs published attack tests on a lab target, reads what a sensor on that
target recorded, has a rule engine evaluate pinned detection rules over those
records, and reports two answers for every test: did the technique take effect,
and what did the defense see.
"""
