"""Built-in attention detector: identify a completed turn needing user input."""

from rules_as_programs import rule

SPEC = """Decide whether the agent's completed response directly requires the user to answer before useful progress can continue. Required choices, missing information, requested confirmation, and blocking clarification need a reply. Rhetorical questions, optional offers, and ordinary conclusions do not.
Return ONLY one of: REPLY_NEEDED, NO_REPLY

Input: ## Latest message
Which database should I migrate: staging or production? I need that choice before continuing.
Output: REPLY_NEEDED

Input: ## Latest message
The implementation is complete. Would you like anything else?
Output: NO_REPLY

Input: ## Latest message
I cannot continue until you provide the deployment hostname.
Output: REPLY_NEEDED

Input: ## Latest message
Why did this fail? The logs show the token expired, so I refreshed it and the tests now pass.
Output: NO_REPLY"""


@rule(
    on=["session_stop"],
    inputs=["message"],
    severity="info",
    channel="attention",
    spec=SPEC,
)
def agent_needs_reply(ctx):
    """Detect when an agent is likely waiting for the user's reply."""
    if ctx.paw(SPEC)(ctx.input()) == "REPLY_NEEDED":
        return "Agent likely needs a reply."
