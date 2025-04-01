### New Developer Documentation (docs/developer.md)


# BlueFire-Nexus Developer Documentation

This document provides guidance for developers contributing to the BlueFire-Nexus platform.

## Getting Started

1.  **Prerequisites**: Python 3.10+, Git, `pip`.
2.  **Clone**: Clone the repository.
3.  **Environment**: Set up a Python virtual environment (recommended):
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    # .venv\Scripts\activate   # Windows
    ```
4.  **Dependencies**: Install core and development dependencies:
    ```bash
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
    ```
5.  **Configuration**: Create a `./config.yaml` file (referencing `config/config.example.yaml`) and a `./.env` file for your local development environment.

## Architecture Overview

Familiarize yourself with the platform's structure described in [docs/ARCHITECTURE.md](ARCHITECTURE.md). Key components include:

*   **Entry Points**: `scripts/bluefire.sh` (CLI wrapper) and `src/run_scenario.py` (Python orchestrator).
*   **Configuration**: Handled by `src/core/config.py` (`ConfigManager`), loading `./config.yaml` and `./.env`.
*   **Core Orchestrator**: `src/core/bluefire_nexus.py` (`BlueFireNexus` class) initializes and manages modules.
*   **Core Modules**: Located under `src/core/` subdirectories, implementing specific APT tactics (e.g., `src/core/discovery/`, `src/core/defense_evasion/`).

## Developing Core Modules

When adding or modifying core modules (e.g., implementing a new Defense Evasion technique):

1.  **Location**: Place new module code within the appropriate subdirectory under `src/core/` (e.g., `src/core/defense_evasion/my_new_technique.py`).
2.  **Integration**: Ensure the main class for the module type (e.g., `DefenseEvasion` in `src/core/defense_evasion/defense_evasion.py`) can load and call your new technique/handler.
3.  **`BlueFireNexus`**: Update `src/core/bluefire_nexus.py` if necessary to:
    *   Import and initialize the new/updated module class.
    *   Map the module in `MODULE_MAP`.
    *   Add specific logic in `execute_operation` if the module requires a unique execution pattern (though using standardized handler methods within modules is preferred).
4.  **Configuration**: If the new feature requires configuration, document the necessary keys/structure in `config/config.example.yaml` and ensure the module reads the configuration correctly (usually via the `update_config` method passed by `BlueFireNexus`).
5.  **Logging**: Implement appropriate logging within your module using Python's `logging` module. Get a logger instance typically via `logger = logging.getLogger(__name__)`.
6.  **Error Handling**: Implement robust error handling using try/except blocks.
7.  **Docstrings**: Add clear docstrings to classes, methods, and functions explaining their purpose, arguments, and return values.

## Testing

*   **Framework**: Tests are written using `pytest`.
*   **Location**: Test files should be placed in the `tests/` directory, mirroring the `src/` structure where applicable (e.g., `tests/core/defense_evasion/test_my_new_technique.py`).
*   **Execution**: Run tests using the `pytest` command from the root directory:
    ```bash
    pytest tests/
    ```
*   **Coverage**: Aim for good test coverage. Coverage reports can be generated (see `workflows/tests.yml` for examples):
    ```bash
    pytest tests/ --cov=src --cov-report term-missing
    ```
*   **CI**: Tests are automatically run via GitHub Actions workflows defined in `.github/workflows/` (e.g., `tests.yml`). Ensure your changes pass CI checks.

## Code Style & Quality

*   **Linter/Formatter**: Use tools like `flake8` and `black` (included in `requirements-dev.txt`) to maintain code quality and consistency.
    ```bash
    flake8 src/ tests/
    black src/ tests/
    ```
*   **Static Analysis**: Tools like `bandit` and `semgrep` are run in CI (`workflows/analysis.yml`) to catch potential security issues.

## Contributing

1.  Adhere to the guidelines in the main `README.md` and `CONTRIBUTING.md`.
2.  Ensure your code is well-documented and tested.
3.  Keep pull requests focused on a single feature or bug fix.
4.  Ensure all tests and CI checks pass.

---

For questions, please open an issue on the repository.