import re


def parse_fail2ban_status(output: str) -> dict:
    match = re.search(r'Jail list:\s*(?P<jails>.+)', output)
    jails = []
    if match:
        jails = [item.strip() for item in match.group('jails').split(',') if item.strip()]
    return {'jails': jails, 'raw': output}


def parse_fail2ban_jail_status(output: str) -> dict:
    jail_match = re.search(r'Status for the jail:\s*(?P<jail>.+)', output)
    banned_match = re.search(r'Currently banned:\s*(?P<count>\d+)', output)
    ips_match = re.search(r'Banned IP list:\s*(?P<ips>.*)', output)
    banned_ips = []
    if ips_match and ips_match.group('ips').strip():
        banned_ips = ips_match.group('ips').split()
    return {
        'jail': jail_match.group('jail').strip() if jail_match else 'unknown',
        'currently_banned': int(banned_match.group('count')) if banned_match else 0,
        'banned_ips': banned_ips,
        'raw': output,
    }
