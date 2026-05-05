# Case Study: Healthcare Ransomware (Lab Emulation)

## Objective

Exercise a realistic ransomware-adjacent chain in a lab: initial access simulation, execution staging, persistence touchpoint, and exfiltration signal generation.

## ATT&CK Coverage

- T1566 (Phishing)
- T1059 (Command and Scripting Interpreter)
- T1053 (Scheduled Task/Job)
- T1041 (Exfiltration over C2 Channel)

## Why this matters

Healthcare environments have high operational pressure and lower tolerance for downtime. Detection engineering must prioritize noisy-but-critical attack signals.

## Suggested blue-team actions

1. Tune process creation analytics for suspicious scripted execution.
2. Validate detections for persistence artifacts created by scheduled tasks.
3. Correlate outbound anomalies with command execution lineage.
4. Run this scenario as part of quarterly purple-team validation.