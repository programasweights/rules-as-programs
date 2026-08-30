from rules_as_programs import rule


SPEC = """The input is the exact serialized JSON value of a Codex PreToolUse
/tool_input field. Decide whether a documentation edit adds an internal page
link whose target ends in .md or .mdx. Internal page links should be clean
extensionless routes. External URLs, image or downloadable-asset links, anchor
links, and extensionless internal links are allowed. Reads and prose that only
describes the convention are allowed.
Return ONLY one of: OK, WARNING

Input: {"file_path":"docs/index.mdx","patch":"See [Workers](/workers/index.mdx)."}
Output: WARNING

Input: {"file_path":"docs/index.mdx","patch":"Read [setup](../setup.md#tokens)."}
Output: WARNING

Input: {"file_path":"docs/index.mdx","patch":"See [Workers](/workers/get-started/)."}
Output: OK

Input: {"file_path":"docs/index.mdx","patch":"Download [schema.json](/assets/schema.json)."}
Output: OK"""


@rule(
    id="e3m4bdwj6gqcwpnn",
    name="Use extensionless internal documentation links",
    trigger="PreToolUse",
    spec=SPEC,
)
def extensionless_doc_links(ctx):
    """Use extensionless routes for internal documentation page links."""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
