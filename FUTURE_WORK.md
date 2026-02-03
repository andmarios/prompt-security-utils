# Future Work

## Prompt Guard 2 Integration

### Background

Meta's [Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) is a BERT-based classifier (mDeBERTa-v3) specifically trained for prompt injection and jailbreak detection. Unlike general-purpose LLMs, it outputs labels directly (`benign`, `injection`, `jailbreak`) with confidence scores.

### Why Add It?

| Current Approach | Limitation |
|------------------|------------|
| Regex patterns | Can't catch novel/obfuscated attacks |
| Haiku screening | Costs money per request |
| Ollama (llama3.2:1b) | General-purpose model, not injection-specific |

Prompt Guard 2 offers:
- **Purpose-built**: Trained specifically on injection/jailbreak corpus
- **Fast**: ~18ms on GPU, ~300ms on CPU
- **Free**: Runs locally, no API costs
- **Multilingual**: 86M model supports multiple languages

### Benchmark Performance

From [NeuralTrust comparison](https://neuraltrust.ai/blog/prevent-prompt-injection-attacks-firewall-comparison):

| Dataset | F1 Score |
|---------|----------|
| Jailbreak-classification (in-distribution) | 0.97 |
| Proprietary airline (out-of-distribution) | 0.70 |

**Caveat**: High in-distribution scores may indicate overfitting. Real-world performance varies.

### Size Impact

Current dependencies: ~1MB

Adding Prompt Guard 2:
| Dependency | Size |
|------------|------|
| `torch` (CPU) | ~2GB |
| `transformers` | ~50MB |
| Model weights | ~170-350MB |
| **Total** | **~2.5GB** |

### Implementation Plan

1. **Optional dependency group**:
   ```toml
   [project.optional-dependencies]
   promptguard = [
       "torch>=2.0.0",
       "transformers>=4.30.0",
   ]
   ```

   Install with: `pip install prompt-security-utils[promptguard]`

2. **New config options**:
   ```json
   {
     "screen_method": "promptguard",
     "promptguard_model": "meta-llama/Llama-Prompt-Guard-2-86M",
     "promptguard_device": "cpu"
   }
   ```

3. **Screening module addition** (`screening.py`):
   ```python
   def screen_content_promptguard(content: str) -> ScreenResult | None:
       """Use Prompt Guard 2 for local screening."""
       try:
           from transformers import AutoTokenizer, AutoModelForSequenceClassification
       except ImportError:
           return None  # Optional dependency not installed

       # Load model (cached after first call)
       # Tokenize and classify
       # Return ScreenResult with injection_detected, confidence, etc.
   ```

4. **Hybrid approach**: Fast Prompt Guard first-pass, Haiku for flagged or long content (>512 tokens)

### Limitations to Document

- **512 token limit**: Must chunk longer content
- **Bypassable**: [Research shows](https://medium.com/trendyol-tech/bypassing-metas-llama-firewall-a-case-study-in-prompt-injection-vulnerabilities-fb552b93412b) it can be evaded
- **Open source model**: Attackers can study it to craft bypasses
- **Overfitting concerns**: May not generalize well to novel attacks

### Alternative: ONNX Runtime

To reduce size (~150MB vs ~2GB), the model could be converted to ONNX format:
```toml
[project.optional-dependencies]
promptguard = [
    "onnxruntime>=1.16.0",
    "tokenizers>=0.15.0",
]
```

This requires pre-converting and hosting the ONNX model weights.

### Decision

For now, the current approach (regex + optional Haiku/Ollama) provides good coverage without the 2.5GB size penalty. Prompt Guard 2 integration should be revisited when:
- Users request it
- A lighter integration path emerges (official ONNX weights, smaller torch builds)
- The library is used in contexts where local-only screening is required
