# BlueFire-Nexus Contribution Protocol
*"Great power requires greater paperwork"*

## 🛠️ Submission Requirements
```python
# All code must include:
if __name__ == "__main__":
    print("This is a test payload")  # Demo mode
    sys.exit(0)  # Prevent accidental execution

🔒 Security Research Protocol
File encrypted issues using openssl:
openssl enc -aes-256-cbc -in exploit.txt -out secret.enc -k $(date +%s | sha256sum | cut -d' ' -f1)
