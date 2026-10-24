# Usage Report

## Final Full-Dataset Audit Run

The final audit run executed `python3 code/main.py --requests dataset/deletion_requests.csv --output output.csv` to generate the root-level `output.csv` for all 518 deletion requests.

### Inference & Token Consumption

| Usage Metric | Per-Request Average | Full Dataset Total (518 Requests) |
| --- | ---: | ---: |
| Requests Processed | 1.0 | 518 |
| Hosted LLM Calls | 0 | 0 |
| Model Provider | None (Local Engine) | None (Local Engine) |
| Model Identifier | Deterministic Symbolic Engine | Deterministic Symbolic Engine |
| Input Tokens | 0 | 0 |
| Output Tokens | 0 | 0 |
| Total Tokens | 0 | 0 |
| Hosted Inference Cost | $0.00 | $0.00 |

### Computational Characteristics & Architecture

- **Deterministic Execution:** The deletion-audit agent executes entirely as a deterministic rule-based and graph-correlated Python engine. No external LLM API endpoints or cloud inference tokens were consumed during the dataset evaluation run.
- **Evidence Extraction:** Document and snapshot text extraction uses pure Python standard-library ReportLab stream decoding (`zlib` and `base64.a85decode`) and indexed static visual transcriptions.
- **Portability & Cost:** Zero hosted API costs (\$0.00 total and \$0.00 per request), ensuring instantaneous local reproducibility, zero network dependency, and 100% deterministic outputs across environments.
