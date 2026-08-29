from rules_as_programs import rule

# RAP_MANAGED_FUZZY_V4
SPEC = """Decide whether the agent's completed response directly requires the user to answer before useful progress can continue. Required choices, missing information, requested confirmation, and blocking clarification are violations. Rhetorical questions, optional offers, and ordinary conclusions are allowed.
Return ONLY one of: OK, INFO, WARNING, CRITICAL

Input: Which database should I migrate: staging or production? I need that choice before continuing.
Output: INFO

Input: The implementation is complete. Would you like anything else?
Output: OK

Input: I cannot continue until you provide the deployment hostname.
Output: INFO

Input: Why did this fail? The token expired, so I refreshed it and the tests now pass.
Output: OK"""


@rule(
    id="gn3xtat6av4fy690",
    name="Detect when an agent needs a reply",
    trigger="Stop",
    channel="attention",
    spec=SPEC,
)
def detect_when_an_agent_needs_a_reply(ctx):
    """Detect when an agent needs a reply"""
    decision = ctx.paw(SPEC)(ctx.input)
    return ctx.result(decision)
