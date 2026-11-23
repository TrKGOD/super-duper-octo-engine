# Pentest Agent Framework

A Claude Code-based, evidence-driven multi-agent pentesting framework scaffold for authorized security assessments.

## Scope

- Web applications and APIs
- Android/iOS mobile applications
- Cloud environments
- Active Directory

## Architecture

The primary design is a hybrid, evidence-driven multi-agent architecture: an orchestrator coordinates specialized agents, persistent findings/evidence schemas support handoffs, and independent validation reduces false positives. The original Model 1 specialist-agent baseline is preserved under `.claude/agents/model-1/` and `docs/model-1/` for comparison.

## Status

Bootstrap/scaffold only. This repository is not a turnkey autonomous scanner. Network execution is disabled by default; configure an explicitly authorized engagement and review all scope controls before use.

## Safety

Use only against assets for which you have written authorization. Do not commit client data, credentials, tokens, raw evidence, or engagement databases. The command guard is a tripwire, not a sandbox; enforce scope with external isolation and least privilege.

## Getting started

See `CLAUDE.md`, `docs/TECHNICAL_SPEC.md`, `docs/ROADMAP.md`, and `config/engagement.example.json`.
