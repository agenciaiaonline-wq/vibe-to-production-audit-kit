# Security Policy

- Run `vibe_audit.py` on an isolated copy or CI step before promoting AI-generated prototypes to production.
- Never commit client bundle environment overrides containing server keys (`SERVICE_ROLE`, `STRIPE_SECRET_KEY`, LLM keys).
- Report security findings via [Golden Nodalix Studio on LinkedIn](https://www.linkedin.com/in/agency-golden-nodalix-880598438/).
