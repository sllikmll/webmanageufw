import re


def parse_ufw_status_numbered(output: str) -> dict:
    status_match = re.search(r'^Status:\s+(?P<status>\w+)', output, re.MULTILINE)
    rules = []
    for line in output.splitlines():
        match = re.match(r'^\[\s*(?P<number>\d+)\]\s+(?P<to>.+?)\s{2,}(?P<action>[A-Z ]+)\s{2,}(?P<from>.+)$', line.strip())
        if match:
            rules.append({
                'number': int(match.group('number')),
                'to': match.group('to').strip(),
                'action': match.group('action').strip(),
                'from': match.group('from').strip(),
            })
    return {
        'status': status_match.group('status').lower() if status_match else 'unknown',
        'rules': rules,
        'raw': output,
    }


def build_add_rule_command(action: str, port: str, protocol: str, source: str | None, comment: str | None) -> str:
    parts = ['ufw', action]
    if source:
        parts.extend(['from', source, 'to', 'any'])
    parts.extend(['port', port, 'proto', protocol])
    if comment:
        safe_comment = comment.replace("'", '')
        parts.extend(['comment', f"'{safe_comment}'"])
    return ' '.join(parts)


def build_delete_rule_command(rule_number: int) -> str:
    return f"yes | ufw delete {rule_number}"
