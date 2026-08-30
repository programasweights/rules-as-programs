from rules_as_programs import rule

SPEC = """Decide whether this completed assistant response directly requires the user to answer or provide missing information before useful progress can continue. Required choices, blocking clarification, missing credentials, and requested confirmation are positive. Rhetorical questions, optional offers, and ordinary conclusions are allowed.
Return ONLY one of: OK, INFO

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
    return ctx.result(ctx.paw(SPEC)(ctx.input))
