"""Fine-tuning script for Qwen models using LoRA / QLoRA for CodeFort security analysis.

Supports training open-weights Qwen models (e.g., Qwen/Qwen2.5-Coder-7B-Instruct) on the
CodeFort supply-chain security dataset (app/ai/dataset.jsonl).

Requirements (for training host with GPU):
    pip install torch transformers peft trl bitsandbytes datasets accelerate

Usage:
    python app/ai/train_lora.py --model_name "Qwen/Qwen2.5-Coder-7B-Instruct" --epochs 3
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("codefort.ai.trainer")


def train(
    model_name: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
    dataset_path: str = "app/ai/dataset.jsonl",
    output_dir: str = "models/codefort-qwen-lora",
    epochs: int = 3,
    batch_size: int = 2,
    learning_rate: float = 2e-4,
    use_4bit: bool = True,
):
    """Executes parameter-efficient fine-tuning (PEFT / QLoRA) on the target Qwen model."""
    logger.info("Initializing CodeFort Qwen Fine-Tuning Pipeline...")
    logger.info(f"Target Model: {model_name}")
    logger.info(f"Dataset:      {dataset_path}")
    logger.info(f"Output Dir:   {output_dir}")

    # Check for PyTorch and GPU
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer
        from datasets import load_dataset
    except ImportError as exc:
        logger.error(
            "Missing fine-tuning packages. To run GPU training on a server/Colab:\n"
            "pip install torch transformers peft trl bitsandbytes datasets accelerate"
        )
        raise RuntimeError(f"Fine-tuning environment missing dependencies: {exc}") from exc

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Compute Device: {device.upper()}")

    # 1. Load Tokenizer
    logger.info("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 2. Configure 4-bit Quantization (QLoRA)
    quantization_config = None
    if use_4bit and device == "cuda":
        from transformers import BitsAndBytesConfig

        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

    # 3. Load Base Model
    logger.info("Loading base Qwen model weights...")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=quantization_config,
        device_map="auto" if device == "cuda" else None,
        trust_remote_code=True,
    )

    if use_4bit and device == "cuda":
        model = prepare_model_for_kbit_training(model)

    # 4. LoRA Configuration
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 5. Load and Prepare Dataset
    dataset = load_dataset("json", data_files=dataset_path, split="train")

    def format_chat(example):
        return {"text": tokenizer.apply_chat_template(example["messages"], tokenize=False)}

    formatted_dataset = dataset.map(format_chat)

    # 6. Training Arguments
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=4,
        learning_rate=learning_rate,
        logging_steps=1,
        save_strategy="epoch",
        fp16=(device == "cuda" and not torch.cuda.is_bf16_supported()),
        bf16=(device == "cuda" and torch.cuda.is_bf16_supported()),
        optim="paged_adamw_8bit" if (use_4bit and device == "cuda") else "adamw_torch",
        report_to="none",
    )

    # 7. SFT Trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=formatted_dataset,
        dataset_text_field="text",
        max_seq_length=2048,
        tokenizer=tokenizer,
        args=training_args,
    )

    logger.info("Starting training loop...")
    trainer.train()

    # 8. Save LoRA Adapter
    logger.info(f"Saving fine-tuned adapter weights to {output_dir}...")
    trainer.model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info("Fine-tuning completed successfully!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CodeFort Qwen LoRA Fine-Tuner")
    parser.add_argument("--model_name", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    parser.add_argument("--dataset_path", default="app/ai/dataset.jsonl")
    parser.add_argument("--output_dir", default="models/codefort-qwen-lora")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--no_4bit", action="store_true")
    args = parser.parse_args()

    train(
        model_name=args.model_name,
        dataset_path=args.dataset_path,
        output_dir=args.output_dir,
        epochs=args.epochs,
        use_4bit=not args.no_4bit,
    )
