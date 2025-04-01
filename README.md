# BlueFire-Nexus

A comprehensive Advanced Persistent Threat (APT) simulation platform designed for security testing, red team operations, and threat hunting within controlled environments.

## Overview

BlueFire-Nexus provides a framework for simulating various APT techniques and tactics, primarily based on the MITRE ATT&CK® framework. It allows security professionals to test detection capabilities, validate security controls, and understand complex attack chains in a safe and isolated lab setting.

**Disclaimer:** This tool is intended for **educational and authorized security testing purposes only** in isolated environments. Unauthorized use or deployment against systems without explicit permission is strictly prohibited. Always adhere to the [Ethical Use Policy](legal/ethical_guidelines.md).

## Features

BlueFire-Nexus is built around a modular architecture, simulating various stages of an APT lifecycle:

*   **Execution:** Manages the execution of commands and payloads.
*   **Command & Control (C2):** Simulates C2 communication channels (e.g., DNS, HTTP) for implant control. (Configuration in `config.yaml` under `modules.command_control.c2_channels`)
*   **Persistence:** Implements techniques to maintain access to compromised systems.
*   **Defense Evasion:** Includes techniques to bypass security controls (e.g., Process Hollowing, Argument Spoofing, Parent PID Spoofing).
*   **Exfiltration:** Simulates methods for extracting data from target environments.
*   **Initial Access:** Models techniques for gaining an initial foothold (e.g., phishing placeholders).
*   **Anti-Detection:** Focuses on techniques to avoid detection by security tools (e.g., Sandbox Evasion, Memory Evasion). (See `src/core/anti_sandbox.py`, `src/core/evasion/anti_detection.py`)
*   **Discovery:** Simulates methods for reconnaissance within a network (e.g., Network/Service Scanning).
*   **Intelligence:** Handles gathering and simulation related to APT group TTPs and threat intelligence.
*   **Network Obfuscator:** Implements techniques for obscuring network traffic patterns.
*   **Resource Development:** Simulates the acquisition and setup of attack infrastructure and capabilities.
*   **Reconnaissance:** Models active and passive information gathering techniques.

*(Note: The implementation depth of each module may vary. Refer to the code in `src/core/` for details.)*

### Security Features

- Modular design based on APT tactics.
- Configuration-driven execution (`config.yaml`).
- Safety mechanisms (configurable in `config.yaml` under `general.safeties`, e.g., `max_runtime`, `allowed_subnets`).
- Placeholder integrations for telemetry (Splunk, Elastic - see `config.yaml` under `telemetry`).

## Installation

```bash
# Clone the repository
git clone <your-repo-url> BlueFire-Nexus
# Example: git clone https://github.com/yourusername/BlueFire-Nexus.git

# Navigate to the project directory
cd BlueFire-Nexus

# Create a Python virtual environment (Recommended)
python -m venv .venv
source .venv/bin/activate  # On Linux/macOS
# .venv\Scripts\activate   # On Windows

# Install dependencies
pip install -r requirements.txt
# Optional: Install dev dependencies
# pip install -r requirements-dev.txt 
```

## Configuration

The main configuration file used by the application is `config.yaml` located in the project root.

1.  **Review/Create `config.yaml`**: If `config.yaml` doesn't exist, a default one might be created on first run (depending on core logic). It's recommended to create it manually based on your needs.
2.  **Use Example as Template**: A detailed template outlining available options and the expected structure (`general`, `modules`, `telemetry`) can be found at `config/config.example.yaml`. You can use this as a reference when creating or modifying your root `config.yaml`.
3.  **Customize `config.yaml`**: Edit the root `config.yaml` file to define your desired simulation parameters, safety settings, module configurations, and telemetry endpoints.

    ```yaml
    # Example structure for ./config.yaml
    general:
      name: "MySimulation"
      mode: "simulation"
      log_level: "INFO" 
      safeties:
        auto_wipe: false # Be careful with auto_wipe!
        max_runtime: 7200 # 2 hours
        allowed_subnets: 
          - "192.168.56.0/24" # Example isolated lab network

    modules:
      # Enable/disable or configure specific modules
      command_control: 
        enabled: true
        c2_channels:
          - protocol: dns
            domain: "apt.internal.lab"
            encryption_key: "{{ env ENCRYPT_KEY }}" # Use env var for secrets

      defense_evasion:
        enabled: true
        # Add specific technique configs if needed

    telemetry: 
      enabled: true
      splunk:
        host: "https://splunk.internal.lab:8088"
        token: "{{ env SPLUNK_TOKEN }}"
      # elastic: ... 
    ```
4.  **Environment Variables**: Note that sensitive values like API keys or encryption keys should be sourced from environment variables (e.g., `{{ env SPLUNK_TOKEN }}`) using a `.env` file or system environment variables. Load dotenv is used (`src/core/config.py`). Create a `.env` file in the root directory:
    ```dotenv
    # .env file
    ENCRYPT_KEY=your_secret_encryption_key_here
    SPLUNK_TOKEN=your_splunk_hec_token_here
    # BLUEFIRE_KILLSWITCH=http://your_killswitch_url (Optional)
    # LOG_LEVEL=DEBUG (Optional, overrides config file)
    ```

## Usage

The primary way to run simulations is via the command-line script:

```bash
# Example: Run the persistence scenario
./scripts/bluefire.sh --profile establish_persistence 

# Example: Run with AI features enabled and DNS exfiltration (if supported)
./scripts/bluefire.sh --profile intel_gathering --ai --exfil dns 
```

This script acts as a wrapper around `src/run_scenario.py`, which likely parses the profile and other arguments to orchestrate the simulation using the `BlueFireNexus` core class.

### Programmatic Usage (Advanced)

It's also possible to import and use the `BlueFireNexus` class directly in Python scripts for more complex integrations or custom scenarios:

```python
from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import config # Access the global config manager

# Ensure config is loaded (BlueFireNexus constructor handles this)
nexus = BlueFireNexus() 

# Access configuration
# c2_config = config.get('modules.command_control', {})

# Execute operations directly (structure depends on module implementation)
# Note: The exact format for 'operation_data' depends on the target module.
try:
    result = nexus.execute_operation("discovery", {
        "scan_type": "network_scan", 
        "targets": ["192.168.56.1/24"]
        # Add other necessary parameters for the discovery module...
    })
    print(f"Discovery Result: {result}")

    result_evasion = nexus.execute_operation("defense_evasion", {
         "technique": "pid_spoofing", 
         "target_command": "powershell.exe -Command ..." 
         # Add other necessary parameters...
    })
    print(f"Evasion Result: {result_evasion}")

except Exception as e:
    print(f"An error occurred: {e}")

```

Refer to the `execute_operation` method in `src/core/bluefire_nexus.py` and the implementations within specific modules (e.g., `src/core/discovery/discovery.py`) for details on required parameters.

## Architecture

The platform is structured as follows:

1.  **Entry Point**: `scripts/bluefire.sh` parses command-line arguments and invokes `src/run_scenario.py`.
2.  **Scenario Runner**: `src/run_scenario.py` likely interprets the profile/arguments and orchestrates the simulation sequence.
3.  **Core Orchestrator**: `src/core/bluefire_nexus.py` contains the `BlueFireNexus` class which initializes and manages all the individual modules. It loads configuration via `ConfigManager` and provides the `execute_operation` method.
4.  **Configuration Manager**: `src/core/config.py` (`ConfigManager` class) handles loading `./config.yaml` and environment variables (`.env`).
5.  **Core Modules**: Located under `src/core/<module_type>/`. Each module (e.g., `CommandControl`, `DefenseEvasion`) encapsulates logic related to a specific APT tactic or function.
6.  **Supporting Code**: Utilities, security functions, loggers potentially reside within `src/core/` or other subdirectories.
7.  **Archived Code**: Unused, experimental, or outdated components are moved to the `archive/` directory for reference.
8.  **Tools**: Separate utilities (like the AI trainer) are in the `tools/` directory.

## Security Considerations

- **Restricted Environment**: **CRITICAL:** Only run BlueFire-Nexus in fully isolated, non-production lab environments where you have explicit authorization.
- **Configuration Safeties**: Carefully configure `general.safeties` in `config.yaml` (e.g., `allowed_subnets`, `max_runtime`) to limit potential impact.
- **Ethical Use**: Strictly adhere to the [Ethical Use Policy](legal/ethical_guidelines.md).
- **Monitoring**: Monitor the simulation environment closely. Utilize the telemetry integrations if configured.
- **Dependencies**: Review dependencies for security vulnerabilities.

## Contributing

Contributions are welcome! Please follow standard GitHub practices:

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

Please review `CONTRIBUTING.md` and `DEVELOPER.MD` (if available/updated) for more details.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors or contributors are not responsible for any misuse or damage caused by this tool. Use it responsibly and ethically.