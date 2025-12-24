import re

def is_valid_log(line: str) -> bool:
    pattern = r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s+(INFO|ERROR|WARN|DEBUG):\s+.+$"
    return bool(re.match(pattern, line.strip()))
