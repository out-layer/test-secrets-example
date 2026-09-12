#!/usr/bin/env bash
#
# One secret model, end to end, against a PUBLISHED test-secrets project.
#
# Two kinds of secret reach a run of this project, and every row below asks
# who gets which:
#
#   the AUTHOR's — profile `author`, named by the manifest inside the wasm,
#                  decrypted into every run; its condition is who may run
#   the CALLER's — profile named in the call's `secrets_ref`, gated by the
#                  condition its owner stored; a whitelist is how an owner hands
#                  one credential to their agents and takes it back
#
# What each row pins (letters follow the plan's catalogue):
#   A1  any caller, no secrets_ref → the author's secret is there, nothing else
#   A10 a manifest with no `network` section leaves egress unrestricted
#   A3  the author's condition is the admission gate: whitelist the owner and a
#       stranger's run is refused before it starts
#   A2  the manifest names a profile nobody stored → refused, naming what to store
#   A7  a caller's profile that defines AUTHOR_SECRET too → refused, both sides named
#   U1  the owner names their own row → present, and the VALUE is the canary
#   U2  a stranger names it → refused by the condition
#   U6  lookalikes of a whitelisted account (a character before it, a label
#       before it) are refused; the exact account is admitted
#   U3  AllowAll on a personal row → a stranger reads it (the documented cost)
#   D1  grant an agent's wallet account → the agent reads it over HTTPS with a
#       body secrets_ref; sender == payer == the agent
#   D4  revoke → refused; the ciphertext on chain is byte-identical
#   D5  a second agent not in the list → refused; added → admitted
#   D6  whitelisting the BOUND name instead of the wallet account → refused
#   C1  the same grant against a connector (connector-probe `secret`) — one model
#
# Not here: D2/D3/D7 (a bound wallet sending on chain and a binding being
# revoked) need the bearer-token machinery of bound_identity_onchain_e2e.sh.
#
# WHAT IT JUDGES BY. On chain: the `execution_completed` event in the
# transaction's own logs, plus the module's returned JSON. Over HTTPS: the
# call's answer. A refused run answers `success:false` with the reason; a run
# that never saw a secret answers `user:false` — the two are told apart.
#
# Needs:
#   PARENT               the project owner, key in the keychain; the CLI's
#                        credentials must be this account (it stores the rows)
#   $PARENT/test-secrets published from THIS directory with ./build.sh (the
#                        manifest build) — see README
#   AGENT_PAYMENT_KEY    (D*, C1) a custody wallet's payment key
#   AGENT_ACCOUNT        (D*, C1) that wallet's implicit account
#   AGENT2_PAYMENT_KEY / AGENT2_ACCOUNT   (D5, optional) a second wallet
#   ASSET                (D6, optional) an account bound to AGENT's wallet
#   AGENT_WALLET_ID      (C1, optional) sent as X-Wallet-Id
#   RUN_C1=0             skip C1 until the coordinator that honours a body
#                        secrets_ref on the connector path is deployed
#
# A2 deletes the `author` profile and stores it again; while it is absent every
# run of the project is refused, including secret_access_conditions_e2e.sh. An
# EXIT trap restores it if this script dies in between — check the last lines
# of the output if a run was interrupted.
#
# Money: ~12 on-chain runs at 0.1 NEAR attached (0.001 charged, rest refunded),
# a few HTTPS calls on the agent's key, three storage deposits, two throwaway
# sub-accounts at 1 NEAR on the first run only.
#
# Run:
#   PARENT=you.testnet ./tests/03_project_model.sh            # dry run: the plan
#   PARENT=you.testnet ./tests/03_project_model.sh --apply

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../../tests/lib/hos_common.sh"

PARENT="${PARENT:-}"
PROJECT="${SECRETS_PROJECT:-}"
CONNECTOR_PROJECT="${CONNECTOR_PROJECT:-connectors.outlayer.testnet/connector-probe}"
AGENT_PAYMENT_KEY="${AGENT_PAYMENT_KEY:-}"
AGENT_ACCOUNT="${AGENT_ACCOUNT:-}"
AGENT2_PAYMENT_KEY="${AGENT2_PAYMENT_KEY:-}"
AGENT2_ACCOUNT="${AGENT2_ACCOUNT:-}"
AGENT_WALLET_ID="${AGENT_WALLET_ID:-}"
ASSET="${ASSET:-}"
DEPOSIT='0.1 NEAR'
FETCH_URL="${FETCH_URL:-$RPC_URL/status}"

MODE="${1:-}"
if [[ "$MODE" != "--apply" ]]; then
  sed -n '3,65p' "$0" >&2
  echo "  Pass --apply to run." >&2
  exit 0
fi
hos_require
command -v outlayer >/dev/null || { echo "✗ the outlayer CLI is not on PATH" >&2; exit 1; }
PROJECT="${PROJECT:-$PARENT/test-secrets}"

# The callers. `pat` is the whitelisted one; `xpat` puts a character before it
# and `sub.pat` a label before it, so between them a whitelist that matched
# substrings would be caught from both ends. `xpat` doubles as the stranger.
MATCHER="pat.$PARENT"
PREFIX_TRAP="xpat.$PARENT"
SUFFIX_TRAP="sub.pat.$PARENT"
STRANGER="$PREFIX_TRAP"

# The fixture helpers and the two run helpers are shared with
# tests/secrets_security_e2e.sh — see tests/lib/secrets_common.sh.
source "$SCRIPT_DIR/../../../tests/lib/secrets_common.sh"

# ── fixture ──────────────────────────────────────────────────────────────────
log "Fixture: the project, the callers, the rows"
PROJECT_VIEW=$(near_view "$CONTRACT_ID" get_project "$(jq -nc --arg p "$PROJECT" '{project_id:$p}')")
if [[ -z "$PROJECT_VIEW" || "$PROJECT_VIEW" == "null" || "$PROJECT_VIEW" == "ERR" ]]; then
  skip "$PROJECT is not deployed — ./build.sh, outlayer upload, outlayer deploy test-secrets (see README)"
  verdict "project secret model"; exit $?
fi
note "project: $PROJECT"

make_account "$MATCHER"     "$PARENT"  '1 NEAR'
make_account "$PREFIX_TRAP" "$PARENT"  '1 NEAR'
make_account "$SUFFIX_TRAP" "$MATCHER" '1 NEAR'

AUTHOR_CANARY="author-$(openssl rand -hex 6)"
USER_CANARY="user-$(openssl rand -hex 6)"
# While A2 has the author row deleted, an interrupted run must not leave the
# project refusing everything: put the row back on the way out.
AUTHOR_ABSENT=false
restore_author() {
  if [[ "$AUTHOR_ABSENT" == true ]]; then
    note "restoring the author profile A2 had deleted"
    store "$PROJECT" author "$(jq -nc --arg v "$AUTHOR_CANARY" '{AUTHOR_SECRET:$v}')" allow-all && AUTHOR_ABSENT=false
  fi
}
trap restore_author EXIT
store "$PROJECT" author "$(jq -nc --arg v "$AUTHOR_CANARY" '{AUTHOR_SECRET:$v}')" allow-all
store "$PROJECT" me     "$(jq -nc --arg v "$USER_CANARY"   '{USER_SECRET:$v}')"   "whitelist:$PARENT"
store "$PROJECT" clash  '{"AUTHOR_SECRET":"not-the-authors"}'                       "whitelist:$PARENT"

# ── A1 the author's secret, for anyone, with no reference ────────────────────
log "A1 the author's secret reaches every run, and nothing else does"
run_as "$PARENT"
[[ "$RUN_OK" == "true" && "$(field .author)" == "true" && "$(field .user)" == "false" ]] \
  && pass "A1 owner: author=true user=false" \
  || fail "A1 owner: success=$RUN_OK author=$(field .author) user=$(field .user) err='$RUN_ERR'"
[[ "$(secret_value AUTHOR_SECRET)" == "$AUTHOR_CANARY" ]] \
  && pass "A1 and the value is this run's canary — read out of the enclave, not assumed" \
  || fail "A1 AUTHOR_SECRET is '$(secret_value AUTHOR_SECRET)', expected the canary"
run_as "$STRANGER"
[[ "$RUN_OK" == "true" && "$(field .author)" == "true" ]] \
  && pass "A1 stranger: the author's AllowAll row reaches them too" \
  || fail "A1 stranger: success=$RUN_OK author=$(field .author) err='$RUN_ERR'"
[[ "$(field .sender)" == "$STRANGER" && "$(field .payer)" == "$STRANGER" ]] \
  && pass "A1 and the run acts as, and is paid by, the signer" \
  || fail "A1 sender=$(field .sender) payer=$(field .payer), expected $STRANGER twice"

# ── A10 a manifest without a network section changes nothing about egress ────
log "A10 the manifest declares no network, so egress stays unrestricted"
run_as "$PARENT" "" "$(jq -nc --arg u "$FETCH_URL" '{fetch_url:$u}')"
case "$(field .fetch)" in
  200*) pass "A10 GET $FETCH_URL → $(field .fetch)" ;;
  *)    fail "A10 fetch answered '$(field .fetch)' (success=$RUN_OK err='$RUN_ERR')" ;;
esac

# ── A3 the author's condition is the admission gate ──────────────────────────
log "A3 whitelist the author's row to the owner: strangers cannot run the project"
set_access "$PROJECT" author "$(whitelist "$PARENT")"
run_as "$STRANGER"
[[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR" \
  && pass "A3 stranger refused before anything ran: $RUN_ERR" \
  || fail "A3 stranger: success=$RUN_OK err='$RUN_ERR' (expected an access-denied refusal)"
run_as "$PARENT"
[[ "$RUN_OK" == "true" && "$(field .author)" == "true" ]] \
  && pass "A3 the owner still runs" \
  || fail "A3 owner: success=$RUN_OK author=$(field .author) err='$RUN_ERR'"
set_access "$PROJECT" author '"AllowAll"'

# ── A2 a declared profile nobody stored ──────────────────────────────────────
log "A2 the manifest names a profile that is not on chain"
AUTHOR_ABSENT=true
delete_row "$PROJECT" author
run_as "$PARENT"
[[ "$RUN_OK" == "false" ]] && grep -q "none are stored" <<<"$RUN_ERR" && grep -q "Project($PROJECT)" <<<"$RUN_ERR" \
  && pass "A2 refused, and the message says what to store: $RUN_ERR" \
  || fail "A2 success=$RUN_OK err='$RUN_ERR' (expected 'none are stored … Project($PROJECT)')"
store "$PROJECT" author "$(jq -nc --arg v "$AUTHOR_CANARY" '{AUTHOR_SECRET:$v}')" allow-all
AUTHOR_ABSENT=false

# ── A7 a caller's key that collides with the author's ────────────────────────
log "A7 a caller's profile defining AUTHOR_SECRET too"
run_as "$PARENT" "$PARENT/clash"
[[ "$RUN_OK" == "false" ]] && grep -q "both define" <<<"$RUN_ERR" && grep -q "AUTHOR_SECRET" <<<"$RUN_ERR" \
  && pass "A7 refused, naming the key: $RUN_ERR" \
  || fail "A7 success=$RUN_OK err='$RUN_ERR' (expected 'both define … AUTHOR_SECRET')"

# ── U1/U2 the caller's own row ───────────────────────────────────────────────
log "U1 the owner names their own row"
run_as "$PARENT" "$PARENT/me"
[[ "$RUN_OK" == "true" && "$(field .author)" == "true" && "$(field .user)" == "true" ]] \
  && pass "U1 author=true user=true" \
  || fail "U1 success=$RUN_OK author=$(field .author) user=$(field .user) err='$RUN_ERR'"
[[ "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
  && pass "U1 and USER_SECRET is the canary" \
  || fail "U1 USER_SECRET is '$(secret_value USER_SECRET)'"

log "U2 a stranger names the owner's row"
run_as "$STRANGER" "$PARENT/me"
[[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR" \
  && pass "U2 refused by the condition: $RUN_ERR" \
  || fail "U2 success=$RUN_OK user=$(field .user) err='$RUN_ERR'"

# ── U6 lookalikes ────────────────────────────────────────────────────────────
log "U6 whitelist $MATCHER: lookalikes are not it"
set_access "$PROJECT" me "$(whitelist "$PARENT" "$MATCHER")"
run_as "$MATCHER" "$PARENT/me"
[[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
  && pass "U6 the whitelisted account reads it" \
  || fail "U6 $MATCHER: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
for trap in "$PREFIX_TRAP" "$SUFFIX_TRAP"; do
  run_as "$trap" "$PARENT/me"
  [[ "$RUN_OK" == "false" ]] \
    && pass "U6 $trap refused" \
    || fail "U6 $trap was ADMITTED by a whitelist naming $MATCHER — a substring match"
done
set_access "$PROJECT" me "$(whitelist "$PARENT")"

# ── U3 the cost of AllowAll ──────────────────────────────────────────────────
log "U3 AllowAll on a personal row"
set_access "$PROJECT" me '"AllowAll"'
run_as "$STRANGER" "$PARENT/me"
[[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
  && pass "U3 a stranger reads it — which is what AllowAll says, and why the interfaces default to a whitelist" \
  || fail "U3 stranger: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
set_access "$PROJECT" me "$(whitelist "$PARENT")"

# ── D* delegation to an agent's wallet ───────────────────────────────────────
if [[ -z "$AGENT_PAYMENT_KEY" || -z "$AGENT_ACCOUNT" ]]; then
  skip "D1/D4/D5/D6/C1 need AGENT_PAYMENT_KEY and AGENT_ACCOUNT (a custody wallet's key and implicit account)"
else
  log "D1 grant the agent's wallet account; the agent names the owner's row over HTTPS"
  set_access "$PROJECT" me "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  call_https "$AGENT_PAYMENT_KEY" "$PROJECT" "$PARENT/me"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" && "$(secret_value USER_SECRET)" == "$USER_CANARY" ]] \
    && pass "D1 the agent reads the owner's canary" \
    || fail "D1 success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
  [[ "$(field .sender)" == "$AGENT_ACCOUNT" && "$(field .payer)" == "$AGENT_ACCOUNT" ]] \
    && pass "D1 sender == payer == the agent's wallet account" \
    || fail "D1 sender=$(field .sender) payer=$(field .payer), expected $AGENT_ACCOUNT twice"

  log "D4 revoke: the whitelist shrinks, the ciphertext does not move"
  BLOB_BEFORE=$(jq -r '.encrypted_secrets' <<<"$(row_of "$PROJECT" me)")
  set_access "$PROJECT" me "$(whitelist "$PARENT")"
  BLOB_AFTER=$(jq -r '.encrypted_secrets' <<<"$(row_of "$PROJECT" me)")
  [[ -n "$BLOB_BEFORE" && "$BLOB_BEFORE" == "$BLOB_AFTER" ]] \
    && pass "D4 update_access left the ciphertext byte-identical" \
    || fail "D4 the ciphertext changed on an access update"
  call_https "$AGENT_PAYMENT_KEY" "$PROJECT" "$PARENT/me"
  [[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR" \
    && pass "D4 the agent is refused: $RUN_ERR" \
    || fail "D4 success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
  set_access "$PROJECT" me "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  call_https "$AGENT_PAYMENT_KEY" "$PROJECT" "$PARENT/me"
  [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
    && pass "D4 re-granted, the same ciphertext decrypts again" \
    || fail "D4 re-grant: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"

  if [[ -n "$AGENT2_PAYMENT_KEY" && -n "$AGENT2_ACCOUNT" ]]; then
    log "D5 a second agent"
    call_https "$AGENT2_PAYMENT_KEY" "$PROJECT" "$PARENT/me"
    [[ "$RUN_OK" == "false" ]] \
      && pass "D5 not in the list → refused" \
      || fail "D5 the second agent read a row that names only the first"
    set_access "$PROJECT" me "$(whitelist "$PARENT" "$AGENT_ACCOUNT" "$AGENT2_ACCOUNT")"
    call_https "$AGENT2_PAYMENT_KEY" "$PROJECT" "$PARENT/me"
    [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
      && pass "D5 added → admitted" \
      || fail "D5 added: success=$RUN_OK user=$(field .user) err='$RUN_ERR'"
    set_access "$PROJECT" me "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  else
    skip "D5 needs AGENT2_PAYMENT_KEY and AGENT2_ACCOUNT"
  fi

  if [[ -n "$ASSET" ]]; then
    log "D6 a grant naming the BOUND account instead of the wallet account"
    set_access "$PROJECT" me "$(whitelist "$PARENT" "$ASSET")"
    call_https "$AGENT_PAYMENT_KEY" "$PROJECT" "$PARENT/me"
    [[ "$RUN_OK" == "false" ]] \
      && pass "D6 refused — grants name the payer, and a binding moves only the name the guest acts as" \
      || fail "D6 a whitelist naming $ASSET admitted the wallet $AGENT_ACCOUNT"
    set_access "$PROJECT" me "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
  else
    skip "D6 needs ASSET (an account bound to the agent's wallet)"
  fi

  if [[ "${RUN_C1:-1}" != "1" ]]; then
    skip "C1 (RUN_C1=0): needs a coordinator that honours a body secrets_ref on the connector path"
  else
  log "C1 the same grant against a connector ($CONNECTOR_PROJECT)"
  PROBE_CANARY="probe-$(openssl rand -hex 6)"
  store "$CONNECTOR_PROJECT" shared "$(jq -nc --arg v "$PROBE_CANARY" '{PROBE_TOKEN:$v}')" "whitelist:$PARENT,$AGENT_ACCOUNT"
  WALLET_HDR=(); [[ -n "$AGENT_WALLET_ID" ]] && WALLET_HDR=(-H "X-Wallet-Id: $AGENT_WALLET_ID")
  call_https "$AGENT_PAYMENT_KEY" "$CONNECTOR_PROJECT" "$PARENT/shared" '{"operation":"secret"}' "${WALLET_HDR[@]}"
  if [[ "$RUN_OK" == "true" ]] && [[ "$(jq -r '.. | objects | select(.key? == "PROBE_TOKEN") | .found // empty' <<<"$RUN_OUT" | head -1)" == "true" ]]; then
    pass "C1 the connector reads the owner's row the agent named — one model"
  else
    fail "C1 success=$RUN_OK err='$RUN_ERR' out=$(head -c 200 <<<"$RUN_OUT")"
  fi
  set_access "$CONNECTOR_PROJECT" shared "$(whitelist "$PARENT")"
  call_https "$AGENT_PAYMENT_KEY" "$CONNECTOR_PROJECT" "$PARENT/shared" '{"operation":"secret"}' "${WALLET_HDR[@]}"
  [[ "$RUN_OK" == "false" ]] \
    && pass "C1 and revoked the same way" \
    || fail "C1 after revocation the connector still read the row"
  fi
fi

verdict "project secret model"
