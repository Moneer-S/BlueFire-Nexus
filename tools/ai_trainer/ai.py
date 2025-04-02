#!/usr/bin/env python3
# tools/ai_trainer/ai.py

import click
import os
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Try importing scapy, warn if unavailable
try:
    from scapy.all import rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy library not found. PCAP preprocessing will not work.")
    print("Install using: pip install scapy")

@click.group()
def cli():
    """
    BlueFire AI CLI:
    Provides commands for AI-based traffic preprocessing and model training.
    """
    pass

@cli.command()
@click.argument('pcap_file')
@click.option('--output', default='preprocessed_data.json', help='Output JSON file for features and labels')
@click.option('--label', required=True, type=int, help='Integer label for this traffic type (e.g., 0 for normal, 1 for C2)')
@click.option('--max-packets', default=10000, help='Maximum packets to process from PCAP')
def preprocess(pcap_file, output, label, max_packets):
    """
    Extract features from pcap file and save as JSON with labels.
    
    Basic features extracted per packet (adjust as needed):
    - Packet length
    - Protocol (TCP=6, UDP=17, Other=0)
    - Inter-arrival time (relative to previous packet in file)
    """
    if not SCAPY_AVAILABLE:
        click.echo("Error: Scapy is required for preprocessing but not installed.", err=True)
        return
        
    click.echo(f"[BlueFire-AI] Preprocessing {pcap_file} with label {label} into {output}...")
    
    features = []
    labels = []
    packet_count = 0
    last_timestamp = None

    try:
        packets = rdpcap(pcap_file)
        click.echo(f"Read {len(packets)} packets from {pcap_file}. Processing max {max_packets}...")
        
        for packet in packets:
            if packet_count >= max_packets:
                click.echo(f"Reached max packet limit ({max_packets}).")
                break
            
            if not packet.haslayer(IP):
                continue # Skip non-IP packets
                
            packet_len = len(packet)
            proto = 0 # Other
            if packet.haslayer(TCP):
                proto = 6
            elif packet.haslayer(UDP):
                proto = 17
                
            current_timestamp = packet.time
            inter_arrival_time = 0
            if last_timestamp is not None:
                inter_arrival_time = float(current_timestamp - last_timestamp)
            last_timestamp = current_timestamp
            
            # Extract more features here if needed (e.g., src/dst ports, flags, payload entropy)
            packet_features = [packet_len, proto, inter_arrival_time]
            features.append(packet_features)
            labels.append(label)
            packet_count += 1
            
            if packet_count % 1000 == 0:
                 click.echo(f"Processed {packet_count} packets...")

    except FileNotFoundError:
        click.echo(f"Error: PCAP file not found: {pcap_file}", err=True)
        return
    except Exception as e:
        click.echo(f"Error processing PCAP file {pcap_file}: {e}", err=True)
        # Optionally log traceback here
        return

    if not features:
         click.echo("Error: No features extracted. Check PCAP content and filters.", err=True)
         return
         
    # Save features and labels
    output_data = {
        "features": features,
        "labels": labels,
        "source_pcap": pcap_file,
        "label_assigned": label,
        "feature_names": ["length", "protocol", "inter_arrival_time"] # Document the features
    }
    
    try:
        with open(output, 'w') as out_f:
            json.dump(output_data, out_f)
        click.echo(f"Preprocessing complete. Saved {len(features)} feature vectors to {output}.")
    except Exception as e:
        click.echo(f"Error writing output JSON file {output}: {e}", err=True)

@cli.command()
@click.argument('input_json_files', nargs=-1, type=click.Path(exists=True))
@click.option('--epochs', default=50, help='Number of epochs to train for')
@click.option('--batch-size', default=64, help='Batch size for training')
@click.option('--output-model', default='bluefire_traffic_model.h5', help='Output model file (HDF5 format)')
@click.option('--val-split', default=0.2, help='Fraction of data for validation split')
def train(input_json_files, epochs, batch_size, output_model, val_split):
    """
    Train a simple NN model using preprocessed feature data from JSON files.
    
    INPUT_JSON_FILES: One or more JSON files created by the preprocess command.
    """
    if not input_json_files:
         click.echo("Error: No input JSON files specified for training.", err=True)
         return
         
    click.echo(f"[BlueFire-AI] Starting training... Epochs={epochs}, BatchSize={batch_size}, Output={output_model}")
    
    all_features = []
    all_labels = []
    num_classes = 0

    # Load data from all specified JSON files
    click.echo("Loading and merging data...")
    for json_file in input_json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            features = data.get("features")
            labels = data.get("labels")
            if features and labels:
                 click.echo(f"Loaded {len(features)} samples from {json_file}")
                 all_features.extend(features)
                 all_labels.extend(labels)
                 # Track the number of unique classes
                 num_classes = max(num_classes, max(labels) + 1) 
            else:
                 click.echo(f"Warning: No features/labels found in {json_file}. Skipping.", err=True)
        except FileNotFoundError:
            click.echo(f"Error: Input JSON file not found: {json_file}", err=True)
            return
        except Exception as e:
            click.echo(f"Error loading or processing {json_file}: {e}", err=True)
            return
            
    if not all_features or not all_labels:
         click.echo("Error: No valid data loaded from input files. Cannot train.", err=True)
         return
         
    click.echo(f"Total samples loaded: {len(all_features)}. Detected classes: {num_classes}")

    # Convert to NumPy arrays
    X = np.array(all_features)
    y = np.array(all_labels)

    # Basic Data Preprocessing
    # 1. Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    click.echo(f"Scaled features. Shape: {X_scaled.shape}")
    
    # 2. Convert labels to categorical (one-hot encoding)
    y_categorical = tf.keras.utils.to_categorical(y, num_classes=num_classes)
    click.echo(f"Converted labels to categorical. Shape: {y_categorical.shape}")

    # 3. Split data into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(X_scaled, y_categorical, test_size=val_split, random_state=42, stratify=y_categorical)
    click.echo(f"Split data: Train={X_train.shape[0]} samples, Validation={X_val.shape[0]} samples")

    # Build a simple Feedforward Neural Network model
    model = models.Sequential([
        layers.Input(shape=(X_train.shape[1],)), # Input shape based on number of features
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(num_classes, activation='softmax') # Output layer size = number of classes
    ])
    
    model.compile(optimizer='adam', 
                  loss='categorical_crossentropy', 
                  metrics=['accuracy'])
                  
    model.summary(print_fn=click.echo)

    click.echo("Starting model training...")
    history = model.fit(X_train, y_train, 
                      epochs=epochs, 
                      batch_size=batch_size, 
                      validation_data=(X_val, y_val),
                      verbose=1) # Show progress bar

    # Evaluate final model performance on validation set
    val_loss, val_acc = model.evaluate(X_val, y_val, verbose=0)
    click.echo(f"\nTraining complete. Final Validation Accuracy: {val_acc:.4f}, Loss: {val_loss:.4f}")

    # Save the trained model
    try:
        model.save(output_model)
        click.echo(f"Model saved successfully to {output_model}")
    except Exception as e:
         click.echo(f"Error saving model to {output_model}: {e}", err=True)

if __name__ == '__main__':
    cli() 