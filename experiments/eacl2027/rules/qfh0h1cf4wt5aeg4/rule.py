from rules_as_programs import rule


SPEC = """The input is the exact serialized JSON value of a Codex PreToolUse
/tool_input field. Decide whether it creates or changes YAML frontmatter for a
source-document page so that the title does not end with the word Source.
Titles ending in Source are allowed. Edits outside a frontmatter title, reads,
and prose examples that do not modify a page are allowed.
Return ONLY one of: OK, WARNING

Input: {"file_path":"docs/sources/mysql.md","content":"---\ntitle: MySQL Connector\n---"}
Output: WARNING

Input: {"file_path":"docs/sources/redis.md","patch":"---\n- title: Redis Source\n+ title: Redis Integration\n---"}
Output: WARNING

Input: {"file_path":"docs/sources/mysql.md","content":"---\ntitle: MySQL Source\n---"}
Output: OK

Input: {"file_path":"docs/sources/mysql.md","patch":"---\ntitle: MySQL Source\n---\nClarify the connection example."}
Output: OK"""


@rule(
    id="qfh0h1cf4wt5aeg4",
    name="End source-page titles with Source",
    trigger="PreToolUse",
    spec=SPEC,
)
def source_title_suffix(ctx):
    """End source-document frontmatter titles with Source."""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
