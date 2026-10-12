# Party B synthetic effect sandbox root

Copy `implementation/common/*` to `common/` and this folder's code/workflows into a NEW **PUBLIC sandbox organization repository**. Never use the existing research `main` branch or real data.

1. Create branches `v26-requests` (writer proposals allowed) and `v26-protected-effects` (native provider ruleset restricts updates; only A App is bypass actor). Put `.gitkeep` in `proposals/` and `effects/` respectively.
2. Party B admin installs Party A-owned GitHub App **on this one sandbox only**, then configures active ruleset and records actual effective rules / bypass list.
3. Copy `pilot_config.example.json` to `config/pilot_config.json`, fill PUBLIC A/B org, A public key/fingerprint verified out of band, and A App ID. Do not put A private key or GitHub App PEM in B repo.
4. `python prepare_effect.py --nonce v26-allowed-00000001 --target-repo B_ORG/v26-effect-sandbox --description 'synthetic effect'` on `v26-requests`; commit only there. Send SHA-256 output to A administrator, not a guessed hash.
5. `native-denial.yml`: B's Actions token must successfully write unprotected control branch (201) and be refused by the provider when writing protected branch (403/422), without branch movement. A generic 409 conflict without a verified ruleset reason is not enough.
6. A alone runs `manage-ledger.yml` and `gate-effect.yml`. B runs `independent-readback.yml` as a supplemental B-run readback; a truly independent observer must separately verify owner/ruleset custody.
7. Return original GitHub URLs, request IDs, response summaries, key fingerprints and SHA-256 manifest, never secrets.

**Native security boundary:** provider rejects non-A App writers on the protected ref. A App's Python gate applies task semantics voluntarily under the independent A administrative trust domain. No cross-repository atomic revocation claim is justified.
