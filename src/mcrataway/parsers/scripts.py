"""Parse and analyze script files: KubeJS, ComputerCraft, Rhino, .mcfunction."""

import re
from dataclasses import dataclass

# Maximum script file size to analyze (1 MB)
_MAX_SCRIPT_SIZE = 1024 * 1024


@dataclass
class ScriptAnalysis:
    """Results of script file analysis."""

    file_type: str  # "kubejs", "computercraft", "rhino", "mcfunction", "unknown"
    suspicious_patterns: list[dict[str, str]]
    functions_called: list[str]
    network_calls: list[str]
    file_operations: list[str]


def analyze_script(data: bytes, filename: str) -> ScriptAnalysis:
    """Analyze a script file for suspicious patterns."""
    if len(data) > _MAX_SCRIPT_SIZE:
        return ScriptAnalysis(
            file_type="unknown",
            suspicious_patterns=[
                {"type": "oversized", "description": "Script file too large to analyze"}
            ],
            functions_called=[],
            network_calls=[],
            file_operations=[],
        )

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return ScriptAnalysis(
            file_type="unknown",
            suspicious_patterns=[],
            functions_called=[],
            network_calls=[],
            file_operations=[],
        )

    file_type = _detect_type(filename, text)
    patterns: list[dict[str, str]] = []
    functions: list[str] = []
    network: list[str] = []
    file_ops: list[str] = []

    patterns.extend(_check_generic_suspicious(text))
    if file_type == "mcfunction":
        patterns.extend(_check_mcfunction_suspicious(text))
    elif file_type in ("kubejs", "computercraft", "rhino"):
        patterns.extend(_check_js_suspicious(text))

    if file_type == "mcfunction":
        functions = _extract_mcfunction_calls(text)
    else:
        functions = _extract_js_functions(text)
        network = _extract_js_network(text)
        file_ops = _extract_js_file_ops(text)

    return ScriptAnalysis(
        file_type=file_type,
        suspicious_patterns=patterns,
        functions_called=functions,
        network_calls=network,
        file_operations=file_ops,
    )


def _detect_type(filename: str, text: str) -> str:
    """Detect the script type from filename and content."""
    if filename.endswith(".mcfunction"):
        return "mcfunction"
    if "kubejs" in filename.lower():
        return "kubejs"
    if filename.endswith(".lua"):
        return "computercraft"
    if filename.endswith(".js") or filename.endswith(".ts"):
        return "rhino"
    if "function " in text and "/" in text:
        return "mcfunction"
    return "unknown"


def _check_generic_suspicious(text: str) -> list[dict[str, str]]:
    """Check for generic suspicious patterns in any script."""
    patterns: list[dict[str, str]] = []

    suspicious_keywords = [
        (r'^\s*/op\s+\S', "op_command", "op command usage"),
        (r'/gamemode\s+creative', "gamemode", "gamemode change"),
        (r'/give\s+.*command_block', "command_block", "command block giveaway"),
        (r'execute\s+.*at\s+@a\s+run', "execute_all", "execute on all players"),
    ]

    for pattern, ptype, description in suspicious_keywords:
        # re.MULTILINE so that ^ matches at the start of every line,
        # not only at the start of the whole string — `/op` may appear
        # on any line of a multi-line .mcfunction file.
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            patterns.append({"type": ptype, "description": description})

    return patterns


def _check_mcfunction_suspicious(text: str) -> list[dict[str, str]]:
    """Check for suspicious .mcfunction patterns."""
    patterns: list[dict[str, str]] = []

    mcfunction_suspicious = [
        (r'^\s*/data\s+merge', "data_merge", "data merge operation"),
        (r'^\s*/scoreboard\s+objectives\s+remove', "scoreboard_remove", "scoreboard removal"),
        (r'^\s*/kill\s+@e', "kill_all_entities", "kill all entities"),
        (r'^\s*/summon\s+.*custom_name', "summon_named", "summon with custom name"),
    ]

    for pattern, ptype, description in mcfunction_suspicious:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            patterns.append({"type": ptype, "description": description})

    return patterns


def _check_js_suspicious(text: str) -> list[dict[str, str]]:
    """Check for suspicious JavaScript patterns."""
    patterns: list[dict[str, str]] = []

    js_suspicious = [
        (r'Java\.type\s*\(\s*["\']java\.lang\.Runtime', "runtime_exec", "Java Runtime exec access"),
        (r'java\.lang\.ProcessBuilder', "process_builder", "ProcessBuilder usage"),
        (r'java\.net\.URL', "java_net", "Java net URL access"),
        (r'java\.net\.http\.HttpClient', "http_client", "Java HttpClient access"),
        (r'java\.io\.File', "java_io_file", "Java File access"),
        (r'javax\.script\.ScriptEngine', "script_engine", "ScriptEngine eval"),
        (r'\beval\s*\(', "eval", "eval() usage"),
        (r'Function\s*\(\s*["\']', "function_constructor", "Function constructor"),
        (r'fetch\s*\(', "fetch", "fetch() usage"),
    ]

    for pattern, ptype, description in js_suspicious:
        if re.search(pattern, text, re.IGNORECASE):
            patterns.append({"type": ptype, "description": description})

    return patterns


def _extract_mcfunction_calls(text: str) -> list[str]:
    """Extract function call targets from .mcfunction content.

    Handles both ``function <target>`` and the
    ``execute ... run function <target>`` forms. The previous regex
    captured the literal word ``function`` for the execute form because
    ``run\\s+`` was followed by ``function`` (which (\\S+) then matched).
    """
    calls: list[str] = []
    # Form 1: `function <target>` (only when not preceded by `run `)
    for match in re.finditer(r'(?<!run\s)function\s+(\S+)', text):
        calls.append(match.group(1))
    # Form 2: `execute ... run function <target>` — explicit form
    for match in re.finditer(r'execute\s+.*\s+run\s+function\s+(\S+)', text, re.DOTALL):
        target = match.group(1)
        if target not in calls:
            calls.append(target)
    return calls


def _extract_js_functions(text: str) -> list[str]:
    """Extract function calls from JavaScript content."""
    functions: list[str] = []
    for match in re.finditer(r'(\w+)\s*\(', text):
        func_name = match.group(1)
        if func_name not in (
            "function", "if", "for", "while", "return", "new",
            "const", "let", "var", "import", "export",
        ):
            functions.append(func_name)
    return list(set(functions))


def _extract_js_network(text: str) -> list[str]:
    """Extract network-related calls from JavaScript."""
    network: list[str] = []
    network_patterns = [
        r'(?:fetch|XMLHttpRequest|axios)\s*\([^)]*\)',
        r'java\.net\.(?:URL|HttpClient|HttpURLConnection)[^;]*;',
    ]
    for pattern in network_patterns:
        for match in re.finditer(pattern, text):
            network.append(match.group(0))
    return network


def _extract_js_file_ops(text: str) -> list[str]:
    """Extract file operation calls from JavaScript."""
    file_ops: list[str] = []
    file_patterns = [
        r'java\.io\.File[^;]*;',
        r'Files\.(?:read|write|create|delete|walk)[^;]*;',
        r'(?:readFile|writeFile|readFileSync|writeFileSync)\s*\([^)]*\)',
    ]
    for pattern in file_patterns:
        for match in re.finditer(pattern, text):
            file_ops.append(match.group(0))
    return file_ops
