import sys
try:
    from colorama import init as _colorama_init, Fore, Style

    _colorama_init()
except ImportError:
    class _Fore:
        BLACK = '\033[30m';
        RED = '\033[31m';
        GREEN = '\033[32m'
        YELLOW = '\033[33m';
        BLUE = '\033[34m';
        MAGENTA = '\033[35m'
        CYAN = '\033[36m';
        WHITE = '\033[37m';
        RESET = '\033[39m'


    class _Style:
        BRIGHT = '\033[1m';
        NORMAL = '\033[0m';
        RESET_ALL = '\033[0m'


    Fore = _Fore()
    Style = _Style()


def color_for_severity(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return Fore.RED + Style.BRIGHT
    if s == "MEDIUM":
        return Fore.YELLOW + Style.BRIGHT
    if s in ("LOW", "N/A"):
        return Fore.GREEN + Style.BRIGHT
    return Fore.WHITE + Style.NORMAL

