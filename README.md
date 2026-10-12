# v26-effect-sandbox (Party B, synthetic test sandbox)

Public research sandbox for the V26 two-party GitHub authorization pilot. It holds synthetic test data only: no production, clinical, defense, physical-system or customer data, and no credentials.

- `v26-requests`: unprotected branch for synthetic task proposals.
- `v26-protected-effects`: protected branch. A provider-native GitHub ruleset restricts updates, force pushes and deletions; only the independently administered Party A GitHub App may be added as a bypass actor.
- Private signing keys and GitHub App keys are never stored here.

Procedure: see `README_PARTY_B.md`.
