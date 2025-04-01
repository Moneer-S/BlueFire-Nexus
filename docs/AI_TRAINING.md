# AI Model Training Protocol (tools/ai_trainer)

This document describes the process for training the AI model used for traffic mimicry, leveraging the script found in `tools/ai_trainer/ai.py`.

**Note:** This tool requires specific dependencies not included in the main `requirements.txt`. Install them before running:
```bash
# Navigate to the tool directory
cd tools/ai_trainer

# Install dependencies (e.g., tensorflow)
pip install -r requirements.txt

# Navigate back to the project root
cd ../..
```

## 1. Data Collection & Preprocessing

First, capture legitimate network traffic from the application you wish to mimic (e.g., Zoom, Teams). This typically involves using tools like `tcpdump` or Wireshark in your test environment.

```bash
# Example: Capture traffic on port 8801 (adjust interface and port)
sudo tcpdump -i eth0 -w legitimate_traffic.pcap port 8801
```

Next, preprocess the captured PCAP file into a JSON format suitable for the training script using the `preprocess` command:

```bash
# Run from the project root directory
python -m tools.ai_trainer.ai preprocess legitimate_traffic.pcap --output training_data.json
```

*(Note: The current `preprocess` function in `ai.py` is a placeholder. It needs to be implemented with actual PCAP parsing logic (e.g., using Scapy or similar libraries) to extract relevant features for training.)*

## 2. Model Architecture

The script `tools/ai_trainer/ai.py` defines a Sequential Keras model using TensorFlow. The default architecture is an LSTM model:

*   **Input Shape**: Defined in the script (e.g., `(60, 256)` - this depends on how preprocessing shapes the data).
*   **LSTM Layer**: 1 layer with 128 units.
*   **Dense Layer**: 64 units (ReLU activation).
*   **Dropout**: 0.4 rate.
*   **Output Layer**: 3 units (Softmax activation) - *Note: The number of output units should likely correspond to categories of traffic patterns or actions being predicted.*

```python
# Snippet from tools/ai_trainer/ai.py
import tensorflow as tf
from tensorflow.keras import layers

# ... (within the train function)
model = tf.keras.Sequential([
    layers.Input(shape=(60, 256)), # Adjust shape based on preprocessed data
    layers.LSTM(128, return_sequences=False),
    layers.Dense(64, activation='relu'),
    layers.Dropout(0.4),
    layers.Dense(3, activation='softmax') # Adjust output units as needed
])
```

## 3. Training Execution

Train the model using the preprocessed JSON data with the `train` command:

```bash
# Run from the project root directory
python -m tools.ai_trainer.ai train \
  --data training_data.json \
  --epochs 100 \
  --batch-size 32 \
  --output-model mimic_model.h5
```

This will generate a model file (e.g., `mimic_model.h5`) containing the trained weights.

*(Note: The current `train` function uses dummy data loading and training steps. Actual implementation requires converting the JSON data into appropriate tensors and using `model.fit()`.)*

## 4. Purpose & Explanation

The goal of this process is to create a model that learns the characteristics of legitimate network traffic (packet sizes, timings, flow patterns, TLS details, etc., depending on the preprocessing implementation). This trained model could then potentially be used by a BlueFire-Nexus module (e.g., Command & Control, Network Obfuscator) to generate C2 or operational traffic that closely resembles the legitimate baseline, making it harder to detect via network traffic analysis.