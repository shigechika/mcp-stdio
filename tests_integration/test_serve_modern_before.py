"""What serve does with MODERN-marked traffic today (#270 Phase 3 P3-0).

THIS FILE IS EXPECTED TO CHANGE. That is why it is not in
`test_serve_legacy_pin.py`, whose charter is the opposite: that suite must
stay green with ZERO diffs on every later Phase 3 PR, and a single test
inside it that is designed to move would destroy the property — once one
diff is legitimate, every diff needs adjudication instead of being prima
facie a bug.

So the two live apart, and the split is the whole point:

- `test_serve_legacy_pin.py` — the AC2 invariant. A diff there is a bug
  until proven otherwise.
- this file — the before-picture. A diff here is the DELIVERABLE of
  P3-A and P3-B, and its absence in the PR that claims to ship them is
  itself the finding.

Concretely: today serve has no modern face at all. A request carrying
modern per-request `_meta` — the exact positive evidence decision D5's era
predicate will look for — is not special-cased; it falls into the ordinary
sessionless-POST path and gets 400 with serve's hardwired -32000. So does
`server/discover`, which obligation O1 says a 2026-07-28 server MUST
implement. When P3-A lands, `_meta` presence starts routing to validation
(and the code becomes -32602/-32020/-32022); when P3-B lands, discover is
answered with a `resultType: "complete"` DiscoverResult.
"""

from __future__ import annotations

import httpx
import pytest

# Serve's `_error_body` hardwires -32000 on every path today. P3-A ships a
# code-bearing replacement; this constant moving is that PR's signature.
CURRENT_ERROR_CODE = -32000


def _error_of(resp: httpx.Response) -> dict:
    body = resp.json()
    assert "error" in body, f"expected a JSON-RPC error, got {body}"
    return body["error"]


@pytest.mark.timeout(45)
def test_modern_markers_are_not_answered_yet(serve_factory):
    """Modern `_meta` and `server/discover` get today's legacy treatment.

    A dedicated gateway rather than the module-scoped one: this is the
    test most likely to be rewritten by a later PR, and it must not leave
    a shared fixture in a state that rewrite could disturb.
    """
    gateway = serve_factory()

    modern = gateway.post(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        },
        headers={"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"},
    )
    assert modern.status_code == 400
    assert _error_of(modern)["code"] == CURRENT_ERROR_CODE

    discover = gateway.post({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})
    assert discover.status_code == 400
    assert _error_of(discover)["code"] == CURRENT_ERROR_CODE
