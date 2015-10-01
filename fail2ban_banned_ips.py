#!/usr/bin/python2.7

import re
import sh
import itertools
from sh import sudo
from fail2ban_check_jails import Task, Action, InfoExtractor
from pyxshell.common import grep

# TODO: Eliminate external dependencies, including fail2ban_check_jails
# As you can see, TasK, Action, InfoExtractor aren't of much use here
t1 = Task("Get the names of all enabled jails")
t1.action = Action("sudo fail2ban-client status")
t1.action.python_cmd = 'sudo("/usr/local/bin/fail2ban-client", "status")'
"""
Status
|- Number of jail:  9
`- Jail list:       nginx-noscript, postfix, nginx-login, nginx-proxy, nginx-auth, nginx-badbots, fail2ban, sasl, ssh
"""
t1.action.ie = InfoExtractor('get names')
p1 = re.compile(r'([a-zA-Z0-9_-]+(?=, |\n$))+')
match = re.findall(p1, t1.action.get_output())
"""
>>> match
['nginx-noscript', 'postfix', 'nginx-login', 'nginx-proxy', 'nginx-auth', 'nginx-badbots', 'fail2ban', 'sasl', 'ssh']
"""

t2 = Task("Get the banned ips for each jail")
d = {}
ips_line = []
for jail in match:
    o = sudo("fail2ban-client", "status", jail)
    # TODO: eliminate sh module, but implement 'sudo' with subprocess
    """
    >>> o
    Status for the jail: postfix
    |- filter
    |  |- File list:    /var/log/mail.log
    |  |- Currently failed: 17
    |  `- Total failed: 140
    `- action
       |- Currently banned: 7
          |  `- IP list:    217.196.2.132 212.235.31.158 80.174.199.161 74.164.14.171 178.15.66.18 217.92.137.209 121.212.240.175
             `- Total banned:   24
    """
    o | grep('IP list:') > ips_line
    # TODO: eliminate pyxshell module, replace grep with str.find('IP list:')
    """
    >>> ips_line
    [u'   |  `- IP list:\t217.196.2.132 212.235.31.158 80.174.199.161 74.164.14.171 178.15.66.18 217.92.137.209 121.212.240.175 \n']
    """
    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    ips = re.findall(ip_pattern, ips_line[0])
    """
    >>> ips
    [u'217.196.2.132',
     u'212.235.31.158',
     u'80.174.199.161',
     u'74.164.14.171',
     u'178.15.66.18',
     u'217.92.137.209',
     u'121.212.240.175']
    """
    d[jail] = ips


# Print banned ips, unique entries(one ip can be banned in multiple jails):
"""
>>> d.values()          # 2D list
[[u'217.196.2.132', ...], [u'80.174.199.161', ...], ..., [...]]
"""

all_ips = itertools.chain(*d.values())
# itertools.chain creates an <itertools.chain> object which is also an iterable
#all_ips = list(itertools.chain(*d.values()))   # school boy way

unique_all_ips = set(all_ips)
#unique_all_ips = list(set(all_ips))            # school boy way

print("All banned IPs (for all jails):")
print(" ".join(unique_all_ips))
print("\n")
# print banned ips for each jail:
for jail, ips in d.items():
    print('%s:\n %s' % (jail, " ".join(ips)))    # never forget brackets in % (..)
    #print("\n")
