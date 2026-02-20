# AI Context Firewall

An Ollama-compatible API proxy that inspects prompts for prompt injection before forwarding them to a backend LLM. A secondary "inspector" LLM analyzes each request, assigns a risk score, and blocks anything above a configurable threshold.

Read the background: [AI Security at Machine Speed](https://njannasch.dev/blog/ai-security-at-machine-speed/) — part 3 of a series on fast inference, local-first AI, and why security becomes an AI-vs-AI problem.

```
Client ──► Firewall :11434 ──► Inspector LLM (risk analysis)
                │                      │
                │ ◄── score ──────────┘
                │
           score ≤ threshold → forward to backend → response
           score > threshold → block with warning
```

![Dashboard — inspection log with color-coded risk levels](screenshots/dashboard.png)

## Quick Start

```bash
cd src && go build -o ../firewall .
./firewall -config ./config.json
```

This starts:
- **Proxy** on `:11434` — drop-in replacement for your Ollama endpoint
- **Web UI** on `:8080` — inspection dashboard + configuration

### Configuration

Edit `config.json` or use the web UI at `http://localhost:8080/config`:

```json
{
  "backend_url": "http://homelab:11434",
  "inspector_url": "http://homelab:11434",
  "inspector_model": "llama3.2:3b",
  "threshold": 70,
  "active_prompt": "standard",
  "custom_prompt": ""
}
```

| Field | Description |
|---|---|
| `backend_url` | Ollama instance that answers queries |
| `inspector_url` | Ollama instance that runs risk analysis (can be the same) |
| `inspector_model` | Model used for inspection (small/fast recommended) |
| `threshold` | Risk score 0–100, requests above this are blocked |
| `active_prompt` | Inspector prompt preset: `standard`, `strict`, `multilingual`, or `custom` |

Environment variables `BACKEND_URL`, `INSPECTOR_URL`, and `INSPECTOR_MODEL` override config file values.

## Inspector Prompts

Four modes for the inspector LLM:

- **Standard** — general-purpose prompt injection detection
- **Strict** — lower tolerance, flags anything manipulative
- **Multilingual** — detects cross-language injection attempts
- **Custom** — your own prompt, editable via the web UI

## Docker

Run with a local Ollama:

```bash
docker compose --profile local up --build
```

Run with a remote Ollama:

```bash
BACKEND_URL=http://homelab:11434 INSPECTOR_URL=http://homelab:11434 docker compose up --build
```

## Testing

```bash
./test.sh                          # default: http://localhost:11434
./test.sh http://other-host:11434  # custom endpoint
```

Sends benign requests, prompt injection attempts, and hidden instructions to verify the firewall catches them.

## Web UI

- **Dashboard** (`/`) — inspection log with color-coded risk levels (green/yellow/red), auto-refreshes
- **Config** (`/config`) — edit endpoints, model selector (auto-fetched from Ollama), threshold, and inspector prompt
- Light/dark theme toggle, persisted in browser

![Configuration page with model selector and prompt preview](screenshots/config.png)

## How It Works

1. Client sends a request to `/api/chat` or `/api/generate`
2. Firewall extracts the prompt content
3. Inspector LLM analyzes it and returns `{risk_level, score, explanation}`
4. Score ≤ threshold → request forwarded to backend, response streamed back
5. Score > threshold → blocked, client receives a warning message
6. All other Ollama endpoints (`/api/tags`, `/api/show`, etc.) pass through unmodified

### Inspection Detail

The firewall uses Ollama's `format: "json"` parameter to constrain the inspector model's output to valid JSON. The system prompt instructs the model to return exactly:

```json
{"risk_level": "safe", "score": 0, "explanation": "No injection detected"}
```

- `risk_level` — `safe`, `suspicious`, or `malicious`
- `score` — 0 (harmless) to 100 (clearly malicious), compared against the threshold
- `explanation` — human-readable reasoning, shown in the dashboard

If the inspector model returns malformed JSON (possible with very small models), the request is forwarded anyway (fail-open) and the error is logged.

### Performance

The dashboard shows per-request timing: inspection latency, backend latency, and total round-trip time.

If backend and inspector share the same Ollama instance with different models, Ollama keeps both loaded in VRAM simultaneously — no reload penalty. If they don't both fit, Ollama swaps models on each request, adding seconds of latency. A small inspector model (e.g. `llama3.2:3b` at ~2GB) leaves room for larger backend models. Check with `ollama ps`.

Benchmark with `llama3.2:3b` for both inspector and backend on a single NVIDIA GPU (warm, both models in VRAM):

| Request | Score | Action | Inspect | Backend | Total |
|---|---|---|---|---|---|
| "What is the capital of France?" | 0 | forwarded | 833ms | 209ms | 1043ms |
| "Ignore all previous instructions..." | 90 | blocked | 1295ms | — | 1295ms |
| "Summarize this email... `<hidden>...</hidden>`" | 80 | blocked | 1526ms | — | 1526ms |
| "Tell me a joke about programming" | 0 | forwarded | 1000ms | 367ms | 1368ms |

Inspection adds ~1-1.5s. Blocked requests skip the backend entirely.

## License

[AGPL-3.0](LICENSE) — Nils Jannasch (https://njannasch.dev)
