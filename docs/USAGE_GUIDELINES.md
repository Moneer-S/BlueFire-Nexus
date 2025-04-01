# Usage Guidelines for BlueFire-Nexus

This document provides essential guidelines for using the BlueFire-Nexus platform responsibly and effectively.

## 1. Ethical and Legal Compliance

**CRITICAL:** Adherence to ethical principles and legal requirements is paramount.

*   **Authorization:** ALWAYS obtain explicit, written permission before conducting any operations against any system or network.
*   **Environment:** ONLY operate BlueFire-Nexus within designated, isolated laboratory or testing environments.
*   **Scope:** Strictly adhere to the authorized scope of testing.
*   **Review:** Familiarize yourself thoroughly with the [Ethical Use Policy](legal/ethical_guidelines.md) before proceeding.

## 2. Installation and Configuration

*   Follow the setup instructions in the main [README.md](README.md#installation).
*   Pay close attention to the configuration steps outlined in the [README.md](README.md#configuration), especially regarding:
    *   The primary configuration file (`./config.yaml`).
    *   Using the example template (`config/config.example.yaml`).
    *   Setting up environment variables (`.env`) for sensitive data.
    *   Configuring safety parameters (`general.safeties`) appropriate for your test environment.

## 3. Running Simulations

*   The primary method for running simulations is via the command line as described in the [README.md Usage Section](README.md#usage).
    ```bash
    # Example: Run a simulation using a specific profile
    ./scripts/bluefire.sh --profile <profile_name> 
    ```
*   Understand the arguments accepted by `scripts/bluefire.sh` (`--profile`, `--ai`, `--exfil`) and how they relate to the simulation execution controlled by `src/run_scenario.py`.
*   Refer to specific module documentation (if available) or code comments within `src/core/` for details on how different profiles or arguments trigger specific operations and techniques.

## 4. Advanced Usage (Programmatic)

*   For custom integrations or complex scenarios, the `BlueFireNexus` class can be used programmatically. See the example in the [README.md](README.md#programmatic-usage-advanced).
*   Carefully examine the required parameters for `execute_operation` based on the target module's implementation in `src/core/`.

## 5. Monitoring and Analysis

*   Monitor the target test environment during simulation runs.
*   If configured, check telemetry outputs (e.g., Splunk, Elastic) for logged events.
*   Review application logs (default: `logs/bluefire.log`, path configurable in `config.yaml`) for execution details and potential errors.

## 6. Security

*   Never expose BlueFire-Nexus or its C2 channels outside the isolated test environment.
*   Keep dependencies updated (`pip install -r requirements.txt --upgrade`).
*   Treat configuration files and environment variables containing sensitive information securely.

# Usage Guidelines for BlueFire-Nexus

## MITRE ATT&CK Mapping
BlueFire-Nexus emulates adversary techniques mapped to MITRE ATT&CK. For example:
- **Process Injection:** T1055.002 (Process Doppelgänging/Reflective DLL Injection)
- **DNS Exfiltration:** T1041 (Exfiltration Over Command and Control Channel)
- **TLS Certificate Mimicry:** T1573.002 (Encrypted Channel)