"""Reference model of how vmrun 1.17.0 hands program arguments to a Windows guest.

Real-VM evidence (spike VM, PowerShell -File script logging ``[Environment]::CommandLine``):
vmrun wraps EVERY program argument in double quotes and escapes nothing, so ``a b``,
``c"d``, ``plain``, ``e\\f`` arrived as ``"a b" "c"d" "plain" "e\\f"``.
:func:`command_line_to_argv` is an implementation of the Windows parsing rules
(CommandLineToArgvW / MSVCRT 2008+) that is independent of the production code.
"""

from __future__ import annotations


def vmrun_command_line(program: str, args: list[str]) -> str:
    """The guest command line vmrun 1.17.0 builds: every element wrapped in quotes, nothing escaped."""
    return " ".join(f'"{a}"' for a in [program, *args])


def command_line_to_argv(cmdline: str) -> list[str]:
    """Reference CommandLineToArgvW / MSVCRT (2008+) parser.

    argv[0]: up to the closing quote when it starts with one (no escapes), else up
    to the first blank. Later arguments: blanks outside quotes separate; 2n
    backslashes + quote -> n backslashes and the quote toggles quoting; 2n+1
    backslashes + quote -> n backslashes and a literal quote; backslashes not
    followed by a quote are literal; inside quotes ``""`` is a literal quote.
    """
    argv: list[str] = []
    i, n = 0, len(cmdline)
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        end = n if end < 0 else end
        argv.append(cmdline[1:end])
        i = end + 1
    else:
        while i < n and cmdline[i] not in " \t":
            i += 1
        argv.append(cmdline[:i])
    while True:
        while i < n and cmdline[i] in " \t":
            i += 1
        if i >= n:
            return argv
        arg: list[str] = []
        quoted = False
        while i < n:
            ch = cmdline[i]
            if ch == "\\":
                j = i
                while j < n and cmdline[j] == "\\":
                    j += 1
                count = j - i
                if j < n and cmdline[j] == '"':
                    arg.append("\\" * (count // 2))
                    if count % 2:
                        arg.append('"')
                        j += 1
                    i = j
                else:
                    arg.append("\\" * count)
                    i = j
                continue
            if ch == '"':
                if quoted and i + 1 < n and cmdline[i + 1] == '"':
                    arg.append('"')
                    i += 2
                    continue
                quoted = not quoted
                i += 1
                continue
            if ch in " \t" and not quoted:
                break
            arg.append(ch)
            i += 1
        argv.append("".join(arg))
