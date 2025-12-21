import sys
try:
    from colorama import init as _colorama_init, Fore, Style

    _colorama_init()
except ImportError:
    # Fallback minimal ANSI colors
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


def color_for_severity(severity: str) -> str:
    sev = (severity or "").upper()

    color_map = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED + Style.BRIGHT,
        "MEDIUM": Fore.YELLOW + Style.BRIGHT,
        "LOW": Fore.GREEN + Style.BRIGHT,
        "N/A": Fore.GREEN + Style.BRIGHT,
    }

    return color_map.get(sev, Fore.WHITE + Style.NORMAL)