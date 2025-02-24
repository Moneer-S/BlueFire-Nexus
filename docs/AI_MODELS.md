# AI Models Documentation

## Vulnerability Predictor Model
- **Training Data**: Trained on 10,000 labeled web requests, including CVE data for SQL injection and XSS.
- **Accuracy Metrics**:
  - Precision: 92%
  - Recall: 89%
  - F1-Score: 90%
- **Retraining Instructions**: Use the script `src/ai/vulnerability_predictor.py` with updated datasets in CSV format.

## Attack Path Optimizer Model
- **Training Data**: Trained on attack simulation data from 500 penetration tests.
- **Accuracy Metrics**:
  - Reduces attack path discovery time by 30%.
- **Retraining Instructions**: Update training data and run `src/ai/attack_path_optimizer.py`.