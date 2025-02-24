**/legal/ethical_guidelines.md**  

# Ethical Use Policy

## Core Principles  
1. **Authorization**: Obtain written permission for all testing activities.  
2. **Containment**: Restrict operations to designated lab environments.  
3. **Transparency**: Document all test scenarios and outcomes.  

## Authorized Use Cases  
- Vulnerability research in air-gapped networks  
- Security control validation for certified red teams  
- Academic study of attack methodologies  

## Prohibited Actions  
❌ Deployment in production systems  
❌ Testing against third-party assets without authorization  
❌ Modification to bypass safety controls  

## Data Handling  
- Use only synthetic datasets (`/modules/fake_data.py`)  
- Automatically purge logs after 72 hours  
- Never collect real credentials or PII  

## Compliance Monitoring  
1. Weekly audit of test activities  
2. Mandatory killswitch checks every 300 seconds  
3. Immediate reporting of safety mechanism failures  

## Incident Response  
1. Activate killswitch via `CTRL+ALT+K`  
2. Execute full environment wipe:  
```bash
./scripts/wipe.sh --level gutmann  