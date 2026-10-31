# CodeFort & BARQAI API Service

FastAPI backend orchestrating pull-request security scans, multi-engine detection (AST static analysis, typosquatting intelligence, CI/CD workflow linter), and the **BARQAI Explanation Engine** powered by **Qwen3.8-Max** via OpenRouter.

---

## ⚡ Quick Start

### 1. Environment Setup
```bash
# Create virtual environment
uv venv
# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies in editable mode with development tools
uv pip install -e ".[dev]"
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Key settings for BARQAI & Qwen:
```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=qwen/qwen3.8-max-0902
OPENROUTER_REASONING=true
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/codefort
```

### 3. Run the Test Suite
```bash
uv run pytest -v
```
All 21 unit and engine integration tests will run.

### 4. Run the API Server
```bash
uv run uvicorn app.main:app --reload --port 8000
```
Interactive API docs will be available at: `http://localhost:8000/docs`

---

## 🤖 BARQAI AI Engine & Training Pipelines

### On-Demand Standalone PR Scan
Run a full scan against any public or live GitHub repository PR:
```bash
python run_scan.py --repo "codefort-sec/vulnerable-test-repo" --pr 1
```

### 4-Dimensional Benchmark Evaluation Suite
Evaluates the AI model across 4 critical metrics:
1. **Verdict Accuracy**: Correctly classifies `PASS`, `REVIEW`, and `BLOCKED`.
2. **Evidence Grounding**: Cites real code lines, AST nodes, and rules without hallucination.
3. **Remediation Viability**: Generates functional, clean patches for malicious changes.
4. **False Positive Resilience**: Correctly passes benign utility/math changes.

```bash
python -m app.ai.eval_suite
```

### 4-bit LoRA / QLoRA Fine-Tuning Pipeline
Fine-tune open-weights Qwen models (e.g. `Qwen/Qwen2.5-Coder-7B-Instruct`):
```bash
python -m app.ai.train_lora \
  --model_id "Qwen/Qwen2.5-Coder-7B-Instruct" \
  --dataset "app/ai/dataset.jsonl" \
  --output_dir "./qwen-barqai-lora" \
  --epochs 3 \
  --batch_size 2
```

---

## 📁 AI Module Layout
- `app/services/engines/barqai.py`: Qwen3.8-Max inference client with JSON schema auto-repair & deterministic fallback.
- `app/ai/knowledge_base.py`: Domain attack knowledge base & few-shot exemplar retriever.
- `app/ai/dataset.jsonl`: Curated ShareGPT/SFT supply chain security fine-tuning dataset.
- `app/ai/train_lora.py`: Parameter-efficient PEFT/LoRA training pipeline.
- `app/ai/eval_suite.py`: 4-dimensional benchmark test cases & scoring engine.
- `run_scan.py`: CLI security scan entrypoint.
