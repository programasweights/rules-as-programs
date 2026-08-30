from rules_as_programs import rule


SPEC = """This is the license-header sub-rule extracted from a broader
instruction; porting provenance and THIRD-PARTY-NOTICES updates need cross-event
context and are outside this benchmark rule. The input is the exact serialized
JSON value of a Codex PreToolUse /tool_input field. Decide whether it creates a
C# or C++ source or test file without a copyright or license header, or
explicitly removes such a header. New .cs, .cpp, .cc, .cxx, or .h files need a
standard header. Editing an existing file with a partial patch that neither
shows nor removes its header is allowed because the unseen header cannot be
judged. Non-source files and reads are allowed.
Return ONLY one of: OK, WARNING

Input: {"file_path":"src/Parser.cs","content":"namespace Demo; public class Parser {}"}
Output: WARNING

Input: {"file_path":"tests/parser.cpp","patch":"- // Copyright (c) .NET Foundation\n- // Licensed under the MIT license."}
Output: WARNING

Input: {"file_path":"src/Parser.cs","content":"// Copyright (c) .NET Foundation\n// Licensed under the MIT license.\nnamespace Demo;"}
Output: OK

Input: {"file_path":"src/Parser.cs","patch":"Add a bounds check in Parse()."}
Output: OK"""


@rule(
    id="sr09vpkt60y74r0q",
    name="Retain license headers in C# and C++ files",
    trigger="PreToolUse",
    spec=SPEC,
)
def retain_license_headers(ctx):
    """Retain license headers in C# and C++ source and test files."""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
