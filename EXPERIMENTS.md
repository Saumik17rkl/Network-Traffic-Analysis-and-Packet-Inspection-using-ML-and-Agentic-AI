# 🧪 EXPERIMENTS.md — CompactNetTrace: Lightweight Network Traffic Analysis

## 1. Experimental Setup
| Component | Description |
|------------|--------------|
| **Goal** | Hybrid flow + packet lightweight ML pipeline for intrusion detection and agentic response |
| **Compute** | 8 GB RAM laptop, Dual-core CPU (no GPU used) |
| **Environment** | Python 3.10, CPU-only PyTorch + scikit-learn |
| **Runtime** | < 25 minutes full pipeline on 10k flow samples |

---

## 2. Datasets
| Dataset | Description | Sampling Strategy |
|----------|--------------|-------------------|
| NSL-KDD | Classic benchmark for intrusion detection | 10,000 samples (balanced) |
| UNSW-NB15 (subset) | Modern flow-level IDS dataset | Random 1% subset |
| Synthetic Scapy flows | Generated with randomized packet count, TTL jitter, payload noise | 500 synthetic flows |

Synthetic data uses:
- Randomized packet sizes ±10%
- Random TTL variation (32–128)
- Flow-level labels for attack vs benign
- Exported as CSV (NetFlow-like fields)

---

## 3. Models & Hyperparameters

### Flow-level Models
| Model | Params | Description |
|--------|----------|--------------|
| Logistic Regression | `C=1.0`, `penalty=l2`, `solver='liblinear'` | Fast baseline |
| Random Forest | `n_estimators=50`, `max_depth=8` | Balanced accuracy vs size |
| Isolation Forest | `n_estimators=75`, `max_samples=0.6` | Unsupervised anomaly baseline |

### Packet-level CNN (PyTorch)
| Layer | Config |
|--------|----------|
| Conv1D | in=1, out=16, kernel=3 |
| Conv1D | in=16, out=32, kernel=3 |
| FC | 64 → 2 |
| Activation | ReLU + Softmax |
| Sequence Length | 128 bytes |
| Optimizer | Adam (`lr=1e-3`) |
| Epochs | 5 (CPU-only) |

---

## 4. Agentic FSM Parameters
| Parameter | Value | Meaning |
|------------|--------|----------|
| `prob_threshold_investigate` | 0.4 | Enter Investigating |
| `prob_threshold_report` | 0.6 | Escalate to Reporting |
| `prob_threshold_contain` | 0.8 | Trigger Containment |
| `containment_duration` | 3 | Auto-release after 3 alerts |

---

## 5. Evaluation Metrics
| Metric | Description |
|----------|--------------|
| Precision / Recall / F1 | Classification effectiveness |
| ROC-AUC | Binary performance |
| Inference Time (ms/flow) | Latency per flow/packet |
| Model Size (MB) | Disk footprint |
| Memory Footprint (MB) | Runtime overhead |
| Detection Latency | Time to agentic escalation |

---

## 6. Reproducibility
- Random seed: `42`
- Data split: 70% train / 15% val / 15% test
- Models serialized with `joblib` and `onnx`
- Results reproducible on CPU-only laptop
