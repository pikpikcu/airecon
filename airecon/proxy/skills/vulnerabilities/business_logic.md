---
name: business-logic
description: Business logic testing for workflow bypass, state manipulation, and domain invariant violations
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges, or bypass reviews. They require a model of the business, not just payloads.

## Attack Surface

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data or action bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency

## High-Value Targets

- Pricing/cart: price locks, quote to order, tax/shipping computation
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: auth/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially finalize/confirm endpoints
- Identify tokens/flags: stepToken, paymentIntentId, orderStatus, reviewState, approvalId; test reuse across users/sessions
- Document invariants: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription)

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation
- Business selectors: currency, locale, timezone, tax region; vary to trigger rounding and ruleset changes

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests
- Out-of-order: call finalize before verify; refund before capture; cancel after ship
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges

## Key Vulnerabilities

### State Machine Abuse

- Skip or reorder steps via direct API calls; verify server enforces preconditions on each transition
- Replay prior steps with altered parameters (e.g., swap price after approval but before capture)
- Split a single constrained action into many sub-actions under the threshold (limit slicing)

### Concurrency and Idempotency

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer)
- Abuse idempotency: key scoped to path but not principal → reuse other users' keys; or idempotency stored only in cache
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund

### Numeric and Currency

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order
- Negative amounts, zero-price, free shipping thresholds, minimum/maximum guardrails

### Quotas, Limits, and Inventory

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies
- Distributed counters without strong consistency enabling double-consumption

### Refunds and Chargebacks

- Double-refund: refund via UI and support tool; refund partials summing above captured amount
- Refund after benefits consumed (downloaded digital goods, shipped items) due to missing post-consumption checks

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion)

## Advanced Techniques

### Event-Driven Sagas

- Saga/compensation gaps: trigger compensation without original success; or execute success twice without compensation
- Outbox/Inbox patterns missing idempotency → duplicate downstream side effects
- Cron/backfill jobs operating outside request-time authorization; mutate state broadly

### Microservices Boundaries

- Cross-service assumption mismatch: one service validates total, another trusts line items; alter between calls
- Header trust: internal services trusting X-Role or X-User-Id from untrusted edges
- Partial failure windows: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement

## Bypass Techniques

- Content-type switching (JSON/form/multipart) to hit different code paths
- Method alternation (GET performing state change; overrides via X-HTTP-Method-Override)
- Client recomputation: totals, taxes, discounts computed on client and accepted by server
- Cache/gateway differentials: stale decisions from CDN/APIM that are not identity-aware

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule vs instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume

## Chaining Attacks

- Business logic + race: duplicate benefits before state updates
- Business logic + IDOR: operate on others' resources once a workflow leak reveals IDs
- Business logic + CSRF: force a victim to complete a sensitive step sequence

## Concrete Testing Procedures

### Step 1: Map the Workflow with a Proxy
Intercept all requests during a normal checkout/payment/signup flow using caido or browser_action.
Save each step's request to output/workflow_map.txt:

    # Record each API call in sequence:
    # Step 1: POST /api/cart/add → captures addToCart request
    # Step 2: POST /api/checkout/init → captures checkout init
    # Step 3: POST /api/payment/confirm → captures payment confirm
    curl -s -X GET https://target.com/api/cart -H "Cookie: session=<your_session>" -v 2>&1 | tee output/workflow_step1.txt

### Step 2: Test State Machine — Skip Steps Directly

    # Try calling final step (confirm) without completing earlier steps (init)
    # Replace step tokens with valid session but NO prior initialization
    curl -s -X POST https://target.com/api/checkout/confirm \
      -H "Content-Type: application/json" \
      -H "Cookie: session=<session>" \
      -d '{"order_id":"12345","amount":0}' | tee output/state_skip_test.txt

    # Check: does the server reject this, or does it process a $0 order?
    # SUCCESS (vuln): 200 OK or order created without proper validation

### Step 3: Test Price/Amount Manipulation

    # Intercept cart request and replace server-sent price with 1 cent
    curl -s -X POST https://target.com/api/cart/checkout \
      -H "Content-Type: application/json" \
      -H "Cookie: session=<session>" \
      -d '{"items":[{"id":"prod_123","qty":1,"price":0.01}]}' | tee output/price_tamper.txt

    # Also test negative amounts:
    curl -s -X POST https://target.com/api/cart/checkout \
      -H "Content-Type: application/json" \
      -H "Cookie: session=<session>" \
      -d '{"items":[{"id":"prod_123","qty":1,"price":-9999}]}' | tee output/negative_price.txt

### Step 4: Test Race Condition (Double-Spend / Double-Redeem)

    # Use parallel curl calls to race a one-time coupon or limited resource
    # Bash parallel execution:
    for i in $(seq 1 20); do
      curl -s -X POST https://target.com/api/coupon/redeem \
        -H "Content-Type: application/json" \
        -H "Cookie: session=<session>" \
        -d '{"code":"PROMO10"}' &
    done
    wait | tee output/race_condition_test.txt
    # Count successful responses: grep -c '"success":true' output/race_condition_test.txt
    # If >1 success → race condition confirmed

    # Python concurrent version (more reliable):
    python3 -c "
import requests, concurrent.futures, json
URL = 'https://target.com/api/coupon/redeem'
HEADERS = {'Cookie': 'session=<session>', 'Content-Type': 'application/json'}
DATA = json.dumps({'code': 'PROMO10'})
def redeem(_): return requests.post(URL, headers=HEADERS, data=DATA, timeout=5)
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    results = list(ex.map(redeem, range(20)))
successes = [r.text for r in results if r.status_code == 200]
print(f'Successes: {len(successes)}')
print(successes[:3])
" | tee output/race_condition_python.txt

### Step 5: Test Refund Abuse

    # Step 1: Make a purchase, note order_id
    # Step 2: Submit refund via UI → note refund_id
    # Step 3: Replay same refund request (idempotency test)
    REFUND_ID=$(cat output/refund_id.txt)
    curl -s -X POST https://target.com/api/refund \
      -H "Cookie: session=<session>" \
      -d "{\"order_id\":\"$ORDER_ID\",\"amount\":50}" | tee output/refund_test1.txt
    # Replay same request with same idempotency key:
    curl -s -X POST https://target.com/api/refund \
      -H "Cookie: session=<session>" \
      -d "{\"order_id\":\"$ORDER_ID\",\"amount\":50}" | tee output/refund_test2.txt
    # Check: does second refund succeed? If yes → double refund vulnerability

### Step 6: Test Quota/Limit Bypass

    # Test off-by-one at quota boundary (e.g., free tier = 10 API calls/day)
    for i in $(seq 1 12); do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Cookie: session=<session>" \
        https://target.com/api/limited_endpoint)
      echo "Call $i: $STATUS"
    done | tee output/quota_test.txt
    # After quota hit (429), test if resetting session or using different header bypasses:
    curl -s -X GET https://target.com/api/limited_endpoint \
      -H "Cookie: session=<new_session_same_account>" | tee output/quota_bypass.txt

### Step 7: Verify Persistence (MANDATORY before reporting)

    # After exploit attempt, verify state change persisted in authoritative source
    # Check account balance / order history / credit balance:
    curl -s https://target.com/api/account/balance \
      -H "Cookie: session=<session>" | tee output/balance_verify.txt
    curl -s https://target.com/api/orders?limit=5 \
      -H "Cookie: session=<session>" | tee output/orders_verify.txt
    # ONLY report if you can show DURABLE state change (e.g., negative balance, extra refund shown in history)

## Testing Methodology

1. **Enumerate state machine** - Per critical workflow (states, transitions, pre/post-conditions); note invariants
2. **Build Actor × Action × Resource matrix** - Unauth, basic user, premium, staff/admin; identify actions per role
3. **Test transitions** - Step skipping, repetition, reordering, late mutation (use curl commands from Step 2-3 above)
4. **Introduce variance** - Time, concurrency, channel (mobile/web/API/GraphQL), content-types (use race tests from Step 4)
5. **Validate persistence boundaries** - All services, queues, and jobs re-enforce invariants (use Step 7 verification)

## Validation

1. Show an invariant violation (e.g., two refunds for one charge, negative inventory, exceeding quotas)
2. Provide side-by-side evidence for intended vs abused flows with the same principal
3. Demonstrate durability: the undesired state persists and is observable in authoritative sources (ledger, emails, admin views)
4. Quantify impact per action and at scale (unit loss × feasible repetitions)

## False Positives

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals

## Impact

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection)
- Denial of inventory/services to legitimate users through resource exhaustion
- Privilege retention or unauthorized access to premium features

## Pro Tips

1. Start from invariants and ledgers, not UI—prove conservation of value breaks
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math—flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks
6. Validate role/feature gates at the service that mutates state, not only at the edge
7. Explore end-of-period edges (month-end, trial end, DST) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss
9. Chain with authorization tests (IDOR/Function-level access) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards

## Summary

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.
