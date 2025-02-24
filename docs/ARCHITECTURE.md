# BlueFire-Nexus Architecture

## Threat Model
We follow STRIDE and LINDDUN frameworks to identify and mitigate threats.

### STRIDE Analysis Diagram
![STRIDE Diagram](./docs/stride_diagram.png)
*Note: Create a diagram image (stride_diagram.png) and add it to the docs folder.*

### Module Interactions
```mermaid
graph TD
    A[AI Engine] -->|Generates Behavioral Profiles| B(C2 Orchestrator)
    B -->|Delivers Obfuscated Payloads| C[Polymorphic Generator]
    C -->|Executes via| D[Anti-Forensic Loader]
    D -->|Reports via| E[Covert Channels]
    E -->|Feeds Data to| A
