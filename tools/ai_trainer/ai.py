#!/usr/bin/env python3
"""CLI placeholder for PCAP → JSON preprocessing and dummy Keras training."""

import json

import click
import tensorflow as tf
from tensorflow.keras import layers


@click.group()
def cli() -> None:
    """Traffic preprocessing and model training commands (stub implementation)."""


@cli.command()
@click.argument("pcap_file")
@click.option("--output", default="zoom_training.json", help="Output JSON file")
def preprocess(pcap_file: str, output: str) -> None:
    """Convert PCAP path to a minimal JSON artifact for downstream training stubs.

    Example:
        python3 -m tools.ai_trainer.ai preprocess zoom.pcap --output zoom_training.json
    """
    click.echo(f"[BlueFire-AI] Preprocessing {pcap_file} into {output}...")
    try:
        with open(pcap_file, encoding="utf-8") as f:
            data = f.read()
    except FileNotFoundError:
        data = "dummy data from pcap"

    training_data = {"pcap_data": data, "note": "This is dummy training data."}
    with open(output, "w", encoding="utf-8") as out_f:
        json.dump(training_data, out_f)
    click.echo("Preprocessing complete.")


@cli.command()
@click.option("--data", default="zoom_training.json", help="Training data JSON")
@click.option("--epochs", default=100, help="Number of epochs to train for")
@click.option("--batch-size", default=32, help="Batch size for training")
@click.option("--output-model", default="mimic_model.h5", help="Output model file")
def train(data: str, epochs: int, batch_size: int, output_model: str) -> None:
    """Build and save a tiny placeholder model (no real fitting on tensors).

    Example:
      python3 -m tools.ai_trainer.ai train --data zoom_training.json
          --epochs 100 --batch-size 32 --output-model mimic_model.h5
    """
    click.echo(
        f"[BlueFire-AI] Training with data={data}, epochs={epochs}, "
        f"batch_size={batch_size}, output={output_model}"
    )

    try:
        with open(data, encoding="utf-8") as f:
            training_data = json.load(f)
    except FileNotFoundError:
        click.echo("Training data not found. Using dummy data.")
        training_data = {"dummy": True}

    click.echo(f"Training payload summary: keys={sorted(training_data)}")

    model = tf.keras.Sequential(
        [
            layers.Input(shape=(60, 256)),
            layers.LSTM(128, return_sequences=False),
            layers.Dense(64, activation="relu"),
            layers.Dropout(0.4),
            layers.Dense(3, activation="softmax"),
        ]
    )

    model.compile(optimizer="adam", loss="categorical_crossentropy")
    click.echo("Starting dummy training (placeholder; model.fit not run)...")
    model.save(output_model)
    click.echo("Training complete. Model saved.")


if __name__ == "__main__":
    cli()
