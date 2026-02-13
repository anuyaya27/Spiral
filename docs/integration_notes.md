# Frontend-Backend Integration Notes

## Current Integration
- Frontend is served from `GET /` using root-level `index.html`.
- Frontend flow is now explicit two-step:
  1. Upload file
  2. Click `Analyze texts`
- Analysis does not start during upload.

## Endpoint Contract Used by Frontend
- `POST /compat/upload`
  - Accepts file upload and platform metadata
  - Returns `{ "upload_id": "...", "message_count": N }`
- `POST /compat/uploads/{upload_id}/analyze`
  - Calls OpenAI-backed analyzer and returns full report JSON
- `GET /compat/reports/{upload_id}`
  - Returns latest stored report JSON

## OpenAI Analysis Integration
- Service module: `app/services/llm/openai_client.py`
- Entry function: `analyze_chat_with_llm(messages)`
- Environment variables:
  - `OPENAI_API_KEY` (required)
  - `OPENAI_MODEL` (default `gpt-4o-mini`)

### Prompting and Validation
- System prompt enforces evidence-only analysis and no diagnosis/outcome prediction.
- Developer prompt enforces JSON-only output and exact schema/constraints.
- Output is validated against Pydantic schema (`app/schemas/llm_report.py`).
- On validation failure, backend runs one repair retry asking model to fix schema mismatches.

## Long Conversation Truncation Strategy
To keep latency and token use bounded while preserving evidence quality:
- Keep most recent `K` messages verbatim (currently 120).
- Summarize older messages into compressed context with the model.
- Analyze using compressed older context + recent verbatim messages.

## Privacy Notes
- Raw chat text stays encrypted at rest in DB.
- Analysis service does not log raw message text.
- Final report is stored in `reports.report_json`.
