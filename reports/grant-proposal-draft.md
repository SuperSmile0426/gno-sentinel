# Gno Sentinel — grant proposal draft

## Project summary

Gno Sentinel is open-source security infrastructure for Gno.land that combines Gno-native source analysis with automated package monitoring and security-focused runtime observations. The first deliverable is a deterministic CLI/CI analyzer with validated Gno-specific rules; later milestones connect it to indexed package publication and expose findings through APIs and alerts.

## Goals and deliverables

### Milestone 1 — analyzer foundation

- stable finding schema and CLI;
- Gno-aware source/package model;
- high-confidence rules backed by vulnerable/fixed fixtures;
- deterministic regression suite;
- JSON output suitable for CI and integrations.

### Milestone 2 — chain ingestion

- tx-indexer integration behind a testable interface;
- detection of new package publication events;
- source ingestion and automatic scanning;
- persisted package/finding history.

### Milestone 3 — developer product

- security API;
- webhooks/notifications;
- CI integration and documentation;
- lightweight dashboard for realm/package security history;
- public testnet demonstration and open-source release.

## Impact on Gno.land's developer ecosystem

The project targets a gap explicitly described by the grants program: real-time contract monitoring and auditing. It reuses Gno infrastructure instead of duplicating explorers/indexers and turns upstream security guidance into deterministic, reusable tooling for realm authors, reviewers, CI systems, wallets, and explorers.

## Proposed duration and budget

Initial planning assumption: 3 months, milestone-based, approximately USD 40,000–60,000 depending on the final scope agreed with the Gno engineering/grants team. This is a proposal assumption, not a published Gno grant tier.

## Evidence before submission

Before requesting a full grant, demonstrate:

- a working `gno-sentinel scan` CLI;
- at least three validated Gno-native rules;
- clean/vulnerable fixture pairs;
- a recorded scan of public example/testnet realms;
- a minimal package-publication ingestion proof of concept.
