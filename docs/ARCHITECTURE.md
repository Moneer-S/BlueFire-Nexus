# BlueFire-Nexus Architecture

This document outlines the high-level architecture of the BlueFire-Nexus simulation platform.

## Core Components

The platform follows a modular architecture centered around the `BlueFireNexus` class, which orchestrates various modules representing different APT tactics.

```mermaid
graph LR
    subgraph User Interaction
        A[CLI: scripts/bluefire.sh] --> B(Python Entry: src/run_scenario.py);
    end

    subgraph Configuration
        C[./config.yaml] --> D(ConfigManager: src/core/config.py);
        E[./.env] --> D;
    end

    subgraph Core Logic
        B --> F{BlueFireNexus: src/core/bluefire_nexus.py};
        D --> F;
        F --> G[Core Modules: src/core/...];
        G --> H(Target Environment Interaction);
    end

    subgraph Modules
        subgraph Command & Control
            G --> C2(src/core/command_control/...);
        end
        subgraph Defense Evasion
             G --> DE(src/core/defense_evasion/...);
        end
         subgraph Exfiltration
             G --> EX(src/core/exfiltration/...);
         end
         subgraph Discovery
              G --> DI(src/core/discovery/...);
         end
         subgraph Persistence
             G --> PE(src/core/persistence/...);
         end
         subgraph ... (Other Modules)
              G --> OTH(...);
         end
    end
    
    H --> Telemetry(Telemetry Endpoints - Splunk/Elastic);
    F --> Telemetry;

    style User Interaction fill:#f9f,stroke:#333,stroke-width:2px;
    style Configuration fill:#ccf,stroke:#333,stroke-width:2px;
    style Core Logic fill:#cfc,stroke:#333,stroke-width:2px;
    style Modules fill:#ffc,stroke:#333,stroke-width:2px;

```

**Flow:**

1.  **Entry Point**: The user typically interacts via the command line using `scripts/bluefire.sh`. This script parses arguments (like `--profile`, `--ai`, `--exfil`).
2.  **Scenario Runner**: `bluefire.sh` executes `src/run_scenario.py`, passing along the parsed arguments. This script is responsible for interpreting the scenario/profile and driving the simulation.
3.  **Configuration Loading**: The `ConfigManager` class (`src/core/config.py`) is instantiated (usually by `BlueFireNexus`). It reads configuration settings from `./config.yaml` and sensitive values/overrides from `./.env`.
4.  **Core Orchestrator**: `BlueFireNexus` (`src/core/bluefire_nexus.py`) initializes. It loads the configuration via `ConfigManager` and instantiates all available core modules (e.g., `CommandControl`, `DefenseEvasion`, `Discovery`) found in `src/core/` subdirectories.
5.  **Module Execution**: The scenario runner (`run_scenario.py`) likely calls the `execute_operation` method of the `BlueFireNexus` instance, specifying the target module (e.g., "discovery") and necessary operation data (parameters, targets, etc.).
6.  **Module Logic**: `BlueFireNexus` routes the request to the appropriate module instance. The module executes its specific logic (e.g., performs a network scan, applies an evasion technique), potentially interacting with the target environment.
7.  **Telemetry**: Modules or the core orchestrator may send telemetry data to configured endpoints (e.g., Splunk, Elasticsearch) based on settings in `config.yaml`.

## Key Classes & Files

*   `scripts/bluefire.sh`: Main user-facing entry point.
*   `src/run_scenario.py`: Python script that orchestrates simulation based on arguments.
*   `config.yaml`: Primary configuration file (user-managed).
*   `.env`: Stores sensitive environment variables.
*   `config/config.example.yaml`: Detailed configuration template.
*   `src/core/config.py`: Contains `ConfigManager` for loading config/env vars.
*   `src/core/bluefire_nexus.py`: Contains `BlueFireNexus` class, the central orchestrator.
*   `src/core/<module_type>/<module_name>.py`: Location of individual core modules (e.g., `src/core/discovery/discovery.py`).

## Supporting Components

*   **Archive (`archive/`)**: Contains previously used or experimental code (e.g., polymorphic engine, old utilities) for reference.
*   **Tools (`tools/`)**: Contains separate utility scripts (e.g., `tools/ai_trainer/` for the TensorFlow-based AI trainer).
*   **Workflows (`workflows/`)**: GitHub Actions for CI/CD (testing, analysis).
*   **Tests (`tests/`)**: Contains unit and potentially integration tests (run via `pytest`).

## Threat Model
We follow STRIDE and LINDDUN frameworks to identify and mitigate threats.

### STRIDE Analysis Diagram
![STRIDE Diagram](./docs/stride_diagram.png)
*Note: Create a diagram image (stride_diagram.png) and add it to the docs folder.*
