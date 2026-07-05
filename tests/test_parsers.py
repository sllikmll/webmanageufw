from app.services.fail2ban import parse_fail2ban_status, parse_fail2ban_jail_status
from app.services.ufw import parse_ufw_status_numbered


UFW_SAMPLE = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 9443/tcp                   ALLOW IN    10.0.0.0/8
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

FAIL2BAN_STATUS = """Status
|- Number of jail:	2
`- Jail list:	sshd, nginx-http-auth
"""

FAIL2BAN_JAIL = """Status for the jail: sshd
|- Filter
|  |- Currently failed:	1
|  |- Total failed:	10
|  `- File list:	/var/log/auth.log
`- Actions
   |- Currently banned:	2
   |- Total banned:	3
   `- Banned IP list:	1.2.3.4 5.6.7.8
"""


def test_parse_ufw_status_numbered_extracts_rules():
    parsed = parse_ufw_status_numbered(UFW_SAMPLE)

    assert parsed['status'] == 'active'
    assert parsed['rules'][0]['number'] == 1
    assert parsed['rules'][1]['to'] == '9443/tcp'
    assert parsed['rules'][2]['from'] == 'Anywhere (v6)'


def test_parse_fail2ban_status_extracts_jails():
    parsed = parse_fail2ban_status(FAIL2BAN_STATUS)

    assert parsed['jails'] == ['sshd', 'nginx-http-auth']


def test_parse_fail2ban_jail_status_extracts_banned_ips():
    parsed = parse_fail2ban_jail_status(FAIL2BAN_JAIL)

    assert parsed['jail'] == 'sshd'
    assert parsed['currently_banned'] == 2
    assert parsed['banned_ips'] == ['1.2.3.4', '5.6.7.8']
