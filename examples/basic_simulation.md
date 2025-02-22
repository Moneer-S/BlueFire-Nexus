
---

### **/examples/basic_simulation.md**
```markdown
# Basic Detection Gap Analysis
*"Because hope is not a strategy"*

## 🔧 Setup
```bash
# In isolated lab environment
docker-compose -f docker-compose.test.yml up -d
export BLUEFIRE_SAFEMODE=1  # Enable training wheels

# Generate test payload (Windows)
python src/core/polymorphic_engine.py --output test.exe --tag "[EXERCISE]"

🧪 Execution
from src.operators.payload_injection import GhostInjector

# Safe-mode injection
injector = GhostInjector(target="notepad.exe", safe=True)  
injector.deploy("test.exe", mimic_as="chrome.exe")

# Expected detection timeline
| Tool          | Expected Alert Time | Failure Condition       |
|---------------|---------------------|-------------------------|
| SentinelOne   | <15 minutes         | >30m = Policy failure   |
| CrowdStrike   | <8 minutes          | >15m = Tuning required  |

📊 Analysis
# Sample Splunk Query
index=bluefire sourcetype=injection 
| stats count by process_name 
| where count > 3  # Detect call chain repetition

💡 Lessons Learned
Gap Found: EDR missed API hashing in 68% of test cases

Improvement: Add behavioral rule for indirect syscalls

Hilarious Oversight: AV triggered on test payload's Rickroll meme