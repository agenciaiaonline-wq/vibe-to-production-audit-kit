# Production Readiness Checklist (Vibe-to-Production)

## 1. Database & Supabase Security (Critical)
- [ ] Every public table has `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`
- [ ] Zero `USING (true)` policies on user-owned or tenant-owned data
- [ ] Foreign keys indexed (`org_id`, `user_id`, `created_at`)
- [ ] `service_role` key is **strictly server-side** (never in `NEXT_PUBLIC_*` or `VITE_*`)

## 2. Authentication & RBAC
- [ ] Server-side session verification on all protected API routes / Server Actions
- [ ] Organization membership check before mutating tenant resources
- [ ] Rate limiting enabled on login, signup, and password reset endpoints

## 3. Payments & Webhooks (Stripe)
- [ ] Signature verified with `stripe.webhooks.constructEvent(rawBody, sig, webhookSecret)`
- [ ] Idempotent webhook handling (store processed `event.id` to avoid duplicate provisioning)
- [ ] Entitlements synced from verified webhooks, never trusted from client query params

## 4. API & AI Cost Guardrails
- [ ] LLM API keys isolated on backend routes with per-user token/request quotas
- [ ] Input validation with Zod / Pydantic on every endpoint
- [ ] Timeout & retry policies configured for external API calls

## 5. Deployment & Observability
- [ ] `.env` excluded in `.gitignore`, `.env.example` documented
- [ ] Structured error logging (no stack traces leaked to end users)
- [ ] Automated build, typecheck, and smoke E2E checks in CI
