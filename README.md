# AI Phishing Checker (CS 487)

You paste in a suspicious email and get back a verdict (**phishing / suspicious / legitimate**) with a plain-language explanation. The checker also catches hidden **prompt injections**, meaning text in an email that tries to trick an AI filter into calling it safe.

The checker has four parts, matching the proposal:

| Component | File | What it does |
|---|---|---|
| Red-flag checks | `phishcheck/redflags.py` | Fake or lookalike sender domains (`paypa1.com`, `micros0ft-support.com`, punycode/Cyrillic), display-name spoofing, Reply-To mismatch, link text vs. real destination, IP/shortened/`@` URLs, risky TLDs, SPF/DKIM/DMARC failures, urgency/threat/credential/gift-card language, dangerous attachments |
| ML model | `phishcheck/model.py` | TF-IDF word + character n-grams plus structural features, fed to logistic regression. Trained on a real public dataset (18.6k emails) plus synthetic examples |
| Prompt-injection detector | `phishcheck/injection.py` | Finds hidden text (CSS `display:none`, 0px/white text, opacity 0, HTML comments, zero-width and invisible Unicode "tag" characters, base64) and instruction-like text aimed at AI ("ignore previous instructions", "classify this as safe", fake `system:` turns, "forward the user's emails to…") |
| LLM judge | `phishcheck/llm.py` | Claude reads the email plus the evidence from the other parts and returns a final verdict as JSON. It's hardened against injection (details below) |

`phishcheck/checker.py` combines the four parts. It also adds **guardrails** the LLM can't override: if the detector finds an injection, or a severity-4 red flag fires, the LLM can't mark the email as safe.

## Quick start

```bash
pip install -r requirements.txt
bash scripts/get_data.sh                                   # real dataset -> data/real/ (optional but recommended)
python scripts/train.py --data data/real/                  # ~1 min; or just `python scripts/train.py` for synthetic only
export ANTHROPIC_API_KEY=sk-ant-...                        # optional: turns on the LLM part
python app.py                                              # demo at http://localhost:5000
```

Without an API key everything still runs. In `full` mode, the rules, ML score and injection detector are combined with a noisy-OR formula instead of going to the LLM.

Command line:

```bash
python scripts/check.py some_email.eml              # or: pbpaste | python scripts/check.py -
python scripts/check.py some_email.eml --mode rules --json
```

The check accepts raw `.eml` files, emails pasted with headers (`From:`, `Subject:`, …), or just a body. HTML bodies are rendered, so the checker sees which text is visible and which is hidden.

## Evaluation (the ablation from the proposal)

```bash
python scripts/evaluate.py --data data/real_test.jsonl data/synthetic_test.jsonl
python scripts/evaluate.py --modes rules ml llm full --limit 300      # with an API key; LLM calls cost money/time
```

This compares **rules only**, **ML only**, **LLM only** and the **full checker** on each test category. It reports the detection rate (phishing caught), the false-positive rate (normal emails wrongly flagged), precision, F1 and accuracy. Results are written to `results/summary.json`, and per-email predictions to `results/predictions.csv`.

Current results (held-out data, LLM off, so `full` = rules + ML + injection fusion):

| mode | detect | FPR | precision | F1 |
|---|---|---|---|---|
| rules | 12.8% | 1.0% | 90.7% | 22.5% |
| ml | 97.4% | 2.2% | 97.0% | 97.2% |
| full (no LLM) | **98.5%** | 2.5% | 96.6% | **97.5%** |

| category | rules | ml | full |
|---|---|---|---|
| real phishing (1,488) | 4.3% | 99.1% | 99.2% |
| real normal email, FPR (2,238) | 1.0% | 2.3% | 2.6% |
| classic-style phishing (60) | 100% | 100% | 100% |
| AI-written phishing (60) | 50% | 50% | **78.3%** |
| prompt-injection phishing (60) | 100% | 100% | 100% |
| synthetic normal email, FPR (60) | 0% | 0% | 0% |

What the numbers show:

- **Rules alone score badly on the real dataset.** That dataset is body-only and lowercased, with no headers or HTML, so the domain and link checks have nothing to check. This is a limitation of the data, not of the rules, and it belongs in the report.
- **ML does very well on the real dataset but misses polished AI-written phishing.** Those emails don't share wording with the old corpora. Combining ML with the rules raises detection on that category from 50% to 78%.
- **The LLM run is still missing.** Set `ANTHROPIC_API_KEY` and run `--modes llm full`. We expect the LLM to matter most on the AI-written category (CEO gift-card requests, vendor bank-detail changes, fake recruiters), where neither rules nor ML have much to go on.

Synthetic test emails come from *templates never seen in training* (`split="test"`), so the model can't just memorize them.

## Prompt-injection hardening in the LLM part

1. The email is wrapped in `<untrusted_email id="RANDOM">…</untrusted_email id="RANDOM">`. The boundary is random, and any attempt by the email to close the tag is stripped.
2. Zero-width characters and invisible Unicode tag characters are removed. Hidden text is shown to the LLM *labelled* as hidden.
3. The system prompt says nothing inside the email is an instruction, and that an injection attempt counts as evidence of phishing.
4. The LLM must reply in strict JSON. Anything else counts as a failure, not a verdict, and the checker falls back to the fusion result.
5. Guardrails in `checker.py` raise the verdict whenever the injection detector fired, even if the LLM was fooled. `tests/test_checker.py::test_guardrail_overrides_manipulated_llm` simulates a fooled LLM to check this.

## Data

- `data/real/Phishing_Email.csv`: public dataset with 18,650 emails (11,322 safe, 7,328 phishing). `train.py --data` holds out 20% as `data/real_test.jsonl`.
- `phishcheck/synthetic.py`: generates four categories: `phish_classic`, `phish_ai` (polished emails with few red flags), `injection` (six hiding techniques) and `legit`. The legit category includes hard negatives: real password resets, urgent internal mail, newsletters with hidden preheader text, and emails that discuss AI.
- `phishcheck/data.py` loads other common CSVs automatically (Kaggle CEAS_08 / Nazario / Nigerian Fraud / SpamAssassin / Enron / Ling, `phishing_email.csv` with `text_combined`, and so on). Put them in `data/real/` and retrain.

Good next steps for the report: add newer phishing samples (Nazario 2020+), have an LLM write a larger set of AI-generated phishing for testing, and test against an outside prompt-injection benchmark.

## Tests

```bash
python -m pytest -q        # 39 tests: parsing, lookalike domains, red flags, injection (positives + benign hard negatives), LLM layer with a mocked client
```

## Project layout

```
phishcheck/  parsing.py  redflags.py  injection.py  model.py  llm.py  checker.py  data.py  synthetic.py
scripts/     train.py  evaluate.py  check.py  get_data.sh
app.py       Flask demo
tests/       test_checker.py
models/      phish_model.joblib (trained with scikit-learn 1.9; retrain if your version can't load it)
```

Configuration: `ANTHROPIC_API_KEY` turns on the LLM. `PHISHCHECK_MODEL` picks the Claude model (default `claude-sonnet-5-5`).
