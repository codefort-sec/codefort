"""Fine-tuning script for Qwen models using LoRA / QLoRA for CodeFort security analysis.

================================================================================
⚠️ HARDWARE REQUIREMENT & GPU NOTICE
================================================================================
This script executes 4-bit quantized Low-Rank Adaptation (QLoRA) using PyTorch,
bitsandbytes, and Hugging Face PEFT.

- Target Environment: GPU Training Server / Cloud (e.g. Google Colab T4/A100,
  RunPod, Lambda Labs, AWS EC2 g5, or a local Linux/Windows host with an NVIDIA RTX GPU).
- VRAM Requirement: >= 12GB VRAM for 7B models (e.g. Qwen2.5-Coder-7B-Instruct)
  or >= 6GB VRAM for 1.5B models (e.g. Qwen2.5-Coder-1.5B-Instruct).
- Local CPU Laptops: Running full 4-bit LoRA training on CPU is not supported by bitsandbytes.
  Use the `--dry_run` flag to validate dataset syntax and tokenization locally,
  or export `app/ai/dataset.jsonl` to Google Colab for training.

Google Colab Quickstart:
    !pip install -q torch transformers peft trl bitsandbytes datasets accelerate
    !python app/ai/train_lora.py --model_name "Qwen/Qwen2.5-Coder-7B-Instruct" --epochs 3
================================================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("codefort.ai.trainer")


def validate_dataset_locally(dataset_path: str) -> int:
    """Validates the JSONL dataset format without requiring GPU dependencies."""
    p = Path(dataset_path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")

    valid_count = 0
    with open(p, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                messages = data.get("messages", [])
                if not messages or len(messages) < 2:
                    raise ValueError(f"Line {idx}: must have at least system/user and assistant messages")
                valid_count += 1
            except Exception as e:
                logger.error(f"Dataset error at line {idx}: {e}")
                raise

    logger.info(f"✓ Dataset verified: {valid_count} valid prompt-completion pairs in {dataset_path}")
    return valid_count


def train(
    model_name: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
    dataset_path: str = "app/ai/dataset.jsonl",
    output_dir: str = "models/codefort-qwen-lora",
    epochs: int = 3,
    batch_size: int = 2,
    learning_rate: float = 2e-4,
    use_4bit: bool = True,
    dry_run: bool = False,
):
    """Executes parameter-efficient fine-tuning (PEFT / QLoRA) on the target Qwen model."""
    logger.info("=" * 70)
    logger.info("CODEFORT Barq-AI QWEN LoRA FINE-TUNING PIPELINE")
    logger.info("=" * 70)
    logger.info(f"Target Model: {model_name}")
    logger.info(f"Dataset:      {dataset_path}")
    logger.info(f"Output Dir:   {output_dir}")
    logger.info(f"Epochs:       {epochs}")

    # Validate dataset integrity first
    valid_samples = validate_dataset_locally(dataset_path)

    if dry_run:
        logger.info("[DRY-RUN] Dataset syntax and structure validated successfully.")
        logger.info("[DRY-RUN] Exiting dry-run without downloading model weights or requiring CUDA.")
        return

    # Check for PyTorch and GPU
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer
        from datasets import load_dataset
    except ImportError as exc:
        logger.error(
            "\n[MISSING DEPENDENCIES] To run GPU fine-tuning, install:\n"
            "pip install torch transformers peft trl bitsandbytes datasets accelerate\n"
        )
        raise RuntimeError(f"Fine-tuning environment missing dependencies: {exc}") from exc

    # Pre-flight CUDA verification
    if not torch.cuda.is_available():
        logger.warning("\n" + "!" * 70)
        logger.warning("[GPU NOTICE] NO NVIDIA CUDA GPU DETECTED ON THIS SYSTEM.")
        logger.warning("4-bit QLoRA fine-tuning requires an NVIDIA GPU with CUDA drivers.")
        logger.warning("For local development laptops, please:")
        logger.warning("  1. Run with '--dry_run' to validate your training dataset locally.")
        logger.warning("  2. Upload this repo or 'dataset.jsonl' to Google Colab / RunPod / AWS GPU.")
        logger.warning("!" * 70 + "\n")
        sys.exit(1)

    device = "cuda"
    gpu_name = torch.cuda.get_device_name(0)
    logger.info(f"Compute Device: {device.upper()} ({gpu_name})")

    # 1. Load Tokenizer
    logger.info("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 2. Configure 4-bit Quantization (QLoRA)
    quantization_config = None
    if use_4bit:
        from transformers import BitsAndBytesConfig

        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    # 3. Load Base Model
    logger.info("Loading base Qwen model weights...")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=quantization_config,
        device_map="auto",
        trust_remote_code=True,
    )

    if use_4bit:
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
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        optim="paged_adamw_8bit" if use_4bit else "adamw_torch",
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

    logger.info("Starting fine-tuning loop...")
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
    parser.add_argument("--dry_run", action="store_true", help="Validate dataset and exit without downloading model or requiring GPU")
    args = parser.parse_args()

    train(
        model_name=args.model_name,
        dataset_path=args.dataset_path,
        output_dir=args.output_dir,
        epochs=args.epochs,
        use_4bit=not args.no_4bit,
        dry_run=args.dry_run,
    )
