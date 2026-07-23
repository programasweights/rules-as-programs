from rules_as_programs import rule

# RAP_MANAGED_FUZZY_V1
SPEC = """Decide whether the agent's completed response directly requires the user to answer before useful progress can continue. Required choices, missing information, requested confirmation, and blocking clarification are violations. Rhetorical questions, optional offers, and ordinary conclusions are allowed.
Return ONLY one of: OK, VIOLATION

Input: ## Latest message
Which database should I migrate: staging or production? I need that choice before continuing.
Output: VIOLATION

Input: ## Latest message
The implementation is complete. Would you like anything else?
Output: OK

Input: ## Latest message
I cannot continue until you provide the deployment hostname.
Output: VIOLATION

Input: ## Latest message
Why did this fail? The token expired, so I refreshed it and the tests now pass.
Output: OK"""


@rule(
    id="0d27400c-ed86-5776-8d01-e80a77bec96e",
    name="Detect when an agent needs a reply",
    on=["session_stop"],
    inputs=["message"],
    channel="attention",
    severity="info",
    spec=SPEC,
)
def detect_when_an_agent_needs_a_reply(ctx):
    """Detect when an agent needs a reply"""
    if ctx.paw(SPEC)(ctx.input()) == "VIOLATION":
        return "Agent likely needs a reply."
