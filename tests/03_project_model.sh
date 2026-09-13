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
#   A10 a manifest with no `network` section leaves egress unrestricted, and a
#       manifest that declares a connector_id closes it: same project, same
#       stored row, egress decided purely by the artefact's own manifest
#   A9  the author secret follows the ARTEFACT: pin a version and its manifest
#       is the one that applies
#   A5  the manifest names a DIFFERENT owner: with no row under that account the
#       run is refused naming owner/profile/project; once that account stores one,
#       it reaches the guest — proof the field drives resolution
#   A6  and narrowing that row to Whitelist[second owner] refuses a run signed by
#       the publisher — the field cannot WIDEN reach, the owner's own condition
#       still governs who may run
#   A11 a BROKEN manifest section (over the size cap, not JSON, a profile that
#       is empty or a number) is REFUSED with a message, never a trap — the
#       plan's sentence. A run that proceeds without the author secret also
#       proceeds without the author's admission gate, so an app opened to a
#       circle runs for everyone the moment its manifest is unreadable. Red
#       while the resolver ignores an unreadable section
#   A3  the author's condition is the admission gate: whitelist the owner and a
#       stranger's run is refused before it starts
#   A2  the manifest names a profile nobody stored → refused, naming what to store
#   A7  a caller's profile that defines AUTHOR_SECRET too → refused, both sides
#       named, and its OTHER keys are withheld as well: all or nothing
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
#   OWNER2_HASH          (A5, A6, optional) a NON-ACTIVE version whose manifest
#                        sets author_secrets.owner to $SECOND_OWNER
#   SECOND_OWNER         (A5, A6) that account; its key must be in the legacy
#                        keychain, since it signs its own rows
#   BROKEN_HASHES        (A11, optional) space-separated NON-ACTIVE version keys
#                        whose manifests are deliberately broken: not JSON, a
#                        numeric profile, an empty profile
#   VARIANT_HASH         (A9, A10b, optional) a published but NON-ACTIVE version
#                        of this project whose manifest declares a connector_id
#                        and no network list. Built by swapping manifest.json,
#                        `outlayer upload`, then `add_version set_active:false`.
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
VARIANT_HASH="${VARIANT_HASH:-da3dfed7e525ce9c25cba72458699a89003f3fdfcf7863a5519de97712c8915d}"
BROKEN_HASHES="${BROKEN_HASHES:-f6de6fe107b4823127be26f1c7aef75aa6a9ee171f18751134bd81783f23a15f 8a1d4b29b5371cbba983bdb9d5e8e6b9f1e4acf07abc73c27b3d2fe022ffd2b4 a4cfc6cda55bbd990c6fa18e0d3ba3c8c5672878f5cc28e6cc97a5ad4ea85a08}"
# The published versions of zavodil.testnet/test-secrets and what each is,
# read from their artefacts on 2026-09-13 (list_versions → source → wasm):
#   223fd2dad15da336… ACTIVE — the current code with its manifest
#   d39dfee85c008560… the same code built WITHOUT the manifest feature (A9 v1, C6's SWITCH_TO)
#   da3dfed7e525ce9c… manifest with a connector_id (A10b)
#   31b7894d960e703c… manifest naming owner zavodil2.testnet (A5/A6)
#   f6de6fe107b48231… manifest section that is not JSON (A11)
#   8a1d4b29b5371cbb… manifest with a numeric profile (A11)
#   a4cfc6cda55bbd99… manifest with an empty profile (A11)
#   d17ad0db7f53b8b9… an old build from March, no manifest — not used
# A9's other half: a published, NON-ACTIVE version built WITHOUT the manifest.
NOMANIFEST_HASH="${NOMANIFEST_HASH:-d39dfee85c0085604e516d37f83032ed98abba4a43322ed4b5c455b33c13c8f7}"
OWNER2_HASH="${OWNER2_HASH:-31b7894d960e703c31086072663e9b23a24ccfbda491654c5d788625a37f5613}"
SECOND_OWNER="${SECOND_OWNER:-zavodil2.testnet}"
ROW_HELPER="$SCRIPT_DIR/../../../tests/lib/store_row_for_owner.py"
DEPOSIT='0.1 NEAR'
# The guest's fetch target: the RPC's own /status, on the keyed host. RPC_URL
# may already carry `?apiKey=…`, and a path cannot follow a query string, so
# the URL is rebuilt here rather than appended to. The key stays out of this
# suite's output (FETCH_SHOWN); the worker's own logs are the operator's.
FETCH_KEY="${RPC_URL#*apiKey=}"; [[ "$FETCH_KEY" == "$RPC_URL" ]] && FETCH_KEY=""
FETCH_URL="${FETCH_URL:-https://rpc.${NETWORK}.fastnear.com/status${FETCH_KEY:+?apiKey=$FETCH_KEY}}"
FETCH_SHOWN="${FETCH_URL%%\?*}"

MODE="${1:-}"
if [[ "$MODE" != "--apply" ]]; then
  sed -n '3,95p' "$0" >&2
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
CLASH_CANARY="clash-$(openssl rand -hex 6)"
store "$PROJECT" clash  "$(jq -nc --arg v "$CLASH_CANARY" '{AUTHOR_SECRET:"not-the-authors", USER_SECRET:$v}')" "whitelist:$PARENT"

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
  200*) pass "A10 GET $FETCH_SHOWN → $(field .fetch)" ;;
  *)    fail "A10 fetch answered '$(field .fetch)' (success=$RUN_OK err='$RUN_ERR')" ;;
esac

# ── A10b / A9 the other half: the artefact's manifest decides ────────────────
#
# The SAME project and the SAME stored author row, pinned to a version whose
# manifest declares a `connector_id` and no `network` list. Declaring an id is
# what makes the allowlist mandatory, and an absent list is an EMPTY allowlist,
# so egress must be refused — while the author secret, named by that same
# manifest, must still arrive. Together they show the behaviour travels with the
# wasm rather than with the project.
if [[ -z "$VARIANT_HASH" ]]; then
  skip "A10b/A9 need VARIANT_HASH (a non-active version whose manifest declares a connector_id)"
else
  log "A10b a pinned version whose manifest declares a connector_id"
  run_as "$PARENT" "" "$(jq -nc --arg u "$FETCH_URL" '{fetch_url:$u}')" "$VARIANT_HASH"
  if [[ "$RUN_OK" == "absent" ]]; then
    fail "A10b the pinned run never completed — check the version's URL actually serves its bytes"
  else
    case "$(field .fetch)" in
      200*) fail "A10b egress was ALLOWED ($(field .fetch)) under a manifest declaring a connector_id and no network list" ;;
      "")   fail "A10b the run reported no fetch at all (success=$RUN_OK err='$RUN_ERR')" ;;
      *)    pass "A10b egress refused by the artefact's own manifest: $(field .fetch | head -c 90)" ;;
    esac
    # A9: the same pinned artefact still names the author's profile, so the
    # secret must arrive. Without this the row above would also pass for a
    # version that simply failed to start.
    [[ "$(field .author)" == "true" && "$(secret_value AUTHOR_SECRET)" == "$AUTHOR_CANARY" ]] \
      && pass "A9 and the pinned artefact still received the author's canary — the manifest travels with the wasm" \
      || fail "A9 pinned run: author=$(field .author) secret='$(secret_value AUTHOR_SECRET)' err='$RUN_ERR'"
  fi
  log "A10b the ACTIVE version is untouched by any of that"
  run_as "$PARENT" "" "$(jq -nc --arg u "$FETCH_URL" '{fetch_url:$u}')"
  case "$(field .fetch)" in
    200*) pass "A10b the active version still reaches the network" ;;
    *)    fail "A10b the active version's egress changed: '$(field .fetch)'" ;;
  esac
fi

# ── A5 / A6 the manifest names a different owner ─────────────────────────────
#
# `author_secrets.owner` decides WHOSE row is read. Two directions matter and
# they pull opposite ways: the field must be able to point at another account
# (A5), and it must not let the publisher reach further than that account allows
# (A6). The row is stored by $SECOND_OWNER itself — the CLI encrypts for and
# signs as its own login, so a cross-owner row needs the envelope helper.
if [[ -z "$OWNER2_HASH" || -z "$SECOND_OWNER" ]]; then
  skip "A5/A6 need OWNER2_HASH (a non-active version naming another owner) and SECOND_OWNER"
elif [[ ! -x "$ROW_HELPER" ]]; then
  skip "A5/A6 need $ROW_HELPER"
else
  as_second() { # as_second <method> <json-args> [deposit]
    local out
    out=$(near --quiet contract call-function as-transaction "$CONTRACT_ID" "$1" \
      json-args "$2" prepaid-gas '100.0 Tgas' attached-deposit "${3:-0 NEAR}" \
      sign-as "$SECOND_OWNER" network-config "$NETWORK" sign-with-legacy-keychain send 2>&1) && return 0
    # `update_access` is payable on a contract carrying the deposit fix and
    # refuses any deposit on one that predates it. Either answer is about the
    # CONTRACT's age, never about the condition these rows are testing, so the
    # other spelling is tried before calling it a failure.
    if grep -qi "accept deposit\|not payable" <<<"$out"; then
      near --quiet contract call-function as-transaction "$CONTRACT_ID" "$1" \
        json-args "$2" prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
        sign-as "$SECOND_OWNER" network-config "$NETWORK" sign-with-legacy-keychain send >/dev/null 2>&1
      return $?
    fi
    return 1
  }
  second_row() { # the row as the chain reports it, owned by $SECOND_OWNER
    near_view "$CONTRACT_ID" get_secrets "$(jq -nc --argjson a "$(accessor_json "$PROJECT")" \
      --arg o "$SECOND_OWNER" '{accessor:$a, profile:"author", owner:$o}')"
  }

  log "A5 the manifest names $SECOND_OWNER, who has stored nothing"
  as_second delete_secrets "$(jq -nc --argjson a "$(accessor_json "$PROJECT")" '{accessor:$a, profile:"author"}')"
  for _ in $(seq 1 10); do
    [[ -z "$(jq -r '.encrypted_secrets // empty' <<<"$(second_row)")" ]] && break
    sleep 2
  done
  run_as "$PARENT" "" '{"message":"a5"}' "$OWNER2_HASH"
  if [[ "$RUN_OK" == "false" ]] && grep -q "$SECOND_OWNER" <<<"$RUN_ERR"; then
    pass "A5 refused, and the message names the owner the manifest points at: $(head -c 130 <<<"$RUN_ERR")"
  else
    fail "A5 success=$RUN_OK err='$(head -c 170 <<<"$RUN_ERR")' (expected a refusal naming $SECOND_OWNER)"
  fi

  log "A5 now $SECOND_OWNER stores it"
  A5_CANARY="a5-$(openssl rand -hex 6)"
  # stdout and stderr kept APART: merging them turns a crash into an unusable
  # string and truncates the reason into a one-line verdict.
  HELPER_ERR=$(mktemp)
  CMD=$("$ROW_HELPER" "$PROJECT" author "$SECOND_OWNER" "$(jq -nc --arg v "$A5_CANARY" '{AUTHOR_SECRET:$v}')" 2>"$HELPER_ERR")
  if [[ "$CMD" != near* ]]; then
    fail "A5 the helper produced no command: $(tr '\n' ' ' < "$HELPER_ERR" | head -c 400)"
    rm -f "$HELPER_ERR"
  else
    rm -f "$HELPER_ERR"
    eval "$CMD" >/dev/null 2>&1
    for _ in $(seq 1 10); do
      [[ -n "$(jq -r '.encrypted_secrets // empty' <<<"$(second_row)")" ]] && break
      sleep 2
    done
    run_as "$PARENT" "" '{"message":"a5"}' "$OWNER2_HASH"
    [[ "$RUN_OK" == "true" && "$(secret_value AUTHOR_SECRET)" == "$A5_CANARY" ]] \
      && pass "A5 the other owner's row reached the guest — and the keystore opened an envelope built outside the CLI" \
      || fail "A5 success=$RUN_OK author=$(field .author) value='$(secret_value AUTHOR_SECRET)' err='$(head -c 150 <<<"$RUN_ERR")'"

    log "A6 narrow it to Whitelist[$SECOND_OWNER] and run as the PUBLISHER"
    # `update_access` is payable: a condition is stored bytes, and this one
    # names an account where the row named nobody. The excess returns in the
    # same transaction, so a round tenth covers a one-account whitelist.
    as_second update_access "$(jq -nc --argjson a "$(accessor_json "$PROJECT")" --arg o "$SECOND_OWNER" \
      '{accessor:$a, profile:"author", new_access:{Whitelist:{accounts:[$o]}}}')" '0.1 NEAR' 
    sleep 6
    run_as "$PARENT" "" '{"message":"a6"}' "$OWNER2_HASH"
    if [[ "$RUN_OK" == "false" ]] && grep -qi "denied" <<<"$RUN_ERR"; then
      pass "A6 refused by that owner's condition — naming an owner cannot widen reach"
    elif [[ "$RUN_OK" == "true" ]]; then
      fail "A6 the publisher ran under a row whitelisted to $SECOND_OWNER only"
    else
      fail "A6 refused for another reason: $(head -c 170 <<<"$RUN_ERR")"
    fi
    as_second update_access "$(jq -nc --argjson a "$(accessor_json "$PROJECT")" \
      '{accessor:$a, profile:"author", new_access:"AllowAll"}')" '0.1 NEAR' \
      && note "A6 restored that row to AllowAll" \
      || fail "A6 COULD NOT RESTORE the row to AllowAll — A5 will refuse until it is put back"
  fi
fi

# ── A9, the v1 half: a version with NO manifest carries no author secret ─────
#
# Plan A9: "two versions: v1 without manifest, v2 with → author secret only
# when v2 runs; pinned run of v1 (version_key) has none". The v2 half is the
# VARIANT_HASH row above; this is v1.
if [[ -z "$NOMANIFEST_HASH" ]]; then
  skip "A9 (v1) needs NOMANIFEST_HASH — a published, non-active version built without the manifest feature"
else
  log "A9 a pinned version with NO manifest (${NOMANIFEST_HASH:0:16}…)"
  run_as "$PARENT" "" '{"message":"a9-v1"}' "$NOMANIFEST_HASH"
  if [[ "$RUN_OK" != "true" ]]; then
    fail "A9 v1 did not run: success=$RUN_OK err='$(head -c 150 <<<"$RUN_ERR")'"
  elif [[ "$(field .author)" == "false" ]]; then
    pass "A9 v1 has no author secret — only the version whose manifest declares one receives it"
  else
    fail "A9 v1 received the author secret (author=$(field .author)) — the row reached a version whose manifest never named it"
  fi
fi

# ── A11 a broken manifest section ────────────────────────────────────────────
#
# Judged on the plan's sentence: an unreadable section refuses the run with a
# message that names the manifest. A trap, a hang, a run that receives the
# author's secret anyway, and a run that proceeds WITHOUT it are all failures —
# the last silently drops the admission gate along with the credential.
if [[ -z "$BROKEN_HASHES" ]]; then
  skip "A11 needs BROKEN_HASHES (non-active versions with deliberately broken manifests)"
else
  for BH in $BROKEN_HASHES; do
    log "A11 a pinned version whose manifest is broken (${BH:0:16}…)"
    run_as "$PARENT" "" '{"message":"a11"}' "$BH"
    # The plan's sentence: a section over 64 KB, not JSON, or naming an empty
    # or numeric profile is REFUSED with a message, never a trap. A run that
    # proceeds without the author secret is not a lenient reading of that — it
    # drops the author's admission gate with the secret, so an app the author
    # opened to a circle runs for everyone the moment its manifest is unreadable.
    if [[ "$RUN_OK" == "absent" ]]; then
      fail "A11 ${BH:0:16}… never completed — a broken manifest must not hang the run"
    elif [[ "$RUN_OK" == "true" ]]; then
      fail "A11 ${BH:0:16}… RAN (author=$(field .author)) — the plan refuses a broken manifest; running without the author secret also runs without the author's admission gate"
    else
      grep -qi "manifest" <<<"$RUN_ERR" \
        && pass "A11 ${BH:0:16}… refused, naming the cause: $(head -c 110 <<<"$RUN_ERR")" \
        || fail "A11 ${BH:0:16}… refused for an unrelated reason: $(head -c 150 <<<"$RUN_ERR")"
    fi
  done
fi

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
# All or nothing. The `clash` profile also carries USER_SECRET, which collides
# with nothing — if the merge dropped the clashing name and carried on, the run
# would SUCCEED and that canary would be in the environment. Asserting only the
# refusal above would not notice that change.
# A refused run carries no environment at all, so "the other key is absent" is
# true however the run failed — including for reasons that have nothing to do
# with the collision. The claim that can fail is the opposite one: the run must
# NOT have succeeded while quietly dropping the clashing name.
if [[ "$RUN_OK" == "true" ]]; then
  [[ "$(secret_value USER_SECRET)" != "$CLASH_CANARY" ]] \
    && fail "A7 the run SUCCEEDED with the clashing profile: the collision was dropped, not refused" \
    || fail "A7 the run succeeded and delivered USER_SECRET from the clashing profile"
else
  # "It did not run" is true of a lost transaction and of any unrelated refusal.
  # The claim is narrower: it did not run BECAUSE of the collision.
  [[ "$RUN_OK" == "false" ]] && grep -q "both define" <<<"$RUN_ERR" \
    && pass "A7 the whole profile was withheld, not merely the clashing key — the run never ran" \
    || fail "A7 the run did not happen, and not because of the collision: success=$RUN_OK err='$(head -c 150 <<<"$RUN_ERR")'"
fi

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
  # The traps are separate accounts: an unfunded one, or a lost send, refuses
  # exactly like a whitelist declining a substring. Only the condition counts.
  [[ "$RUN_OK" == "false" ]] && grep -qiE "denied|permission|condition" <<<"$RUN_ERR" \
    && pass "U6 $trap refused by the condition" \
    || fail "U6 $trap: success=$RUN_OK err='$(head -c 150 <<<"$RUN_ERR")' (expected a refusal BY THE CONDITION)"
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
    [[ "$RUN_OK" == "false" ]] && grep -qiE "denied|permission|condition" <<<"$RUN_ERR" \
      && pass "D5 not in the list → refused by the condition" \
      || fail "D5 second agent: success=$RUN_OK err='$(head -c 150 <<<"$RUN_ERR")' (expected a refusal BY THE CONDITION)"
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
    # With use_bound_identity the guest's sender is $ASSET and the payer stays
    # the wallet. Without it both are the wallet, and a refusal would say
    # nothing about WHICH of the two the condition judged.
    https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
      "$(jq -nc --arg o "$PARENT" '{input:{message:"d6"}, secrets_ref:{account_id:$o, profile:"me"}, use_bound_identity:true}')"
    if [[ "$RUN_OK" == "true" ]]; then
      fail "D6 a whitelist naming the BOUND name $ASSET admitted the wallet $AGENT_ACCOUNT — the condition was judged against the sender, not the payer"
    elif grep -qi "denied\|permission" <<<"$RUN_ERR"; then
      pass "D6 refused BY THE CONDITION — grants name the payer, and a binding moves only the name the guest acts as"
    else
      fail "D6 refused for something else, which proves nothing about grants: $(head -c 140 <<<"$RUN_ERR")"
    fi
    # The control: the same key, the same call, the wallet named again. Without
    # it a spent key or an exhausted quota would read as a working access rule.
    set_access "$PROJECT" me "$(whitelist "$PARENT" "$AGENT_ACCOUNT")"
    https_post "$AGENT_PAYMENT_KEY" "$PROJECT" \
      "$(jq -nc --arg o "$PARENT" '{input:{message:"d6-control"}, secrets_ref:{account_id:$o, profile:"me"}, use_bound_identity:true}')"
    [[ "$RUN_OK" == "true" && "$(field .user)" == "true" ]] \
      && pass "D6 and the same key runs once the row names the wallet — the refusal was the condition's" \
      || fail "D6 the control call failed too ($RUN_OK, $(head -c 120 <<<"$RUN_ERR")): the refusal above proves nothing"
    [[ "$(field .sender)" == "$ASSET" && "$(field .payer)" == "$AGENT_ACCOUNT" ]] \
      && pass "D6 and the binding moved only the name: sender=$ASSET, payer=$AGENT_ACCOUNT" \
      || fail "D6 sender='$(field .sender)' payer='$(field .payer)' — expected sender=$ASSET, payer=$AGENT_ACCOUNT"
  else
    skip "D6 needs ASSET (an account bound to the agent's wallet)"
  fi

  if [[ "${RUN_C1:-1}" != "1" ]]; then
    skip "C1 (RUN_C1=0): needs a coordinator that honours a body secrets_ref on the connector path"
  else
  log "C1 the same grant against a connector ($CONNECTOR_PROJECT)"
  PROBE_CANARY="probe-$(openssl rand -hex 6)"
  store "$CONNECTOR_PROJECT" shared "$(jq -nc --arg v "$PROBE_CANARY" '{PROBE_TOKEN:$v}')" "whitelist:$PARENT,$AGENT_ACCOUNT"
  # An EMPTY array's "[@]" is "unbound" to bash 3.2 under set -u, and this
  # suite died here on a machine with no AGENT_WALLET_ID; the +-idiom below
  # expands to nothing instead.
  WALLET_HDR=(); [[ -n "${AGENT_WALLET_ID:-}" ]] && WALLET_HDR=(-H "X-Wallet-Id: $AGENT_WALLET_ID")
  call_https "$AGENT_PAYMENT_KEY" "$CONNECTOR_PROJECT" "$PARENT/shared" '{"operation":"secret"}' ${WALLET_HDR[@]+"${WALLET_HDR[@]}"}
  if [[ "$RUN_OK" == "true" ]] && [[ "$(jq -r '.. | objects | select(.key? == "PROBE_TOKEN") | .found // empty' <<<"$RUN_OUT" | head -1)" == "true" ]]; then
    pass "C1 the connector reads the owner's row the agent named — one model"
  else
    fail "C1 success=$RUN_OK err='$RUN_ERR' out=$(head -c 200 <<<"$RUN_OUT")"
  fi
  set_access "$CONNECTOR_PROJECT" shared "$(whitelist "$PARENT")"
  call_https "$AGENT_PAYMENT_KEY" "$CONNECTOR_PROJECT" "$PARENT/shared" '{"operation":"secret"}' ${WALLET_HDR[@]+"${WALLET_HDR[@]}"}
  # A connector call refused for the DAY'S QUOTA looks exactly like one refused
  # by the condition, and the admitted call just above spends one of that
  # quota. Reading the reason is the whole difference between a test and a
  # coin toss.
  if [[ "$RUN_OK" == "true" ]]; then
    fail "C1 after revocation the connector still read the row"
  elif grep -qi "quota" <<<"$RUN_ERR"; then
    skip "C1 revocation half: the wallet's daily connector quota is spent ($(head -c 90 <<<"$RUN_ERR")) — this says nothing about the grant"
  elif grep -qi "denied\|permission" <<<"$RUN_ERR"; then
    pass "C1 and revoked the same way, refused by the condition"
  else
    fail "C1 refused for an unrelated reason: $(head -c 140 <<<"$RUN_ERR")"
  fi
  fi
fi

verdict "project secret model"
