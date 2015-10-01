#!/usr/bin/python2.7

"""
Get from fail2ban the number of enabled jails.
Get from iptables the number of fail2ban-* chains.
Compare the 2 values.
OK result: values are equal
BAD result: values are NOT equal, so some services are not protected
            by fail2ban.
    Action: restart fail2ban service (Not implemented)

Usage:
    sudo fail2ban_check_jails.py
    fail2ban_check_jails.py -h | --help
    fail2ban_check_jails.py --version
"""
# *.py extension is needed to be able to import it from ipython session.

# docopt throws this err: TypeError: 'module' object is not callable
#import docopt    # creates beautiful CLIs
#arguments = docopt(__doc__, version='Fail2ban_check_jails 0.1', help=True)
import sh
from sh import sudo
import re
import sys


class Task(object):
    """Emulates a shell command, but with a rich behaviour suitable
    for interactive development.

    Initialization and usage:
    >>> t1 = Task("List the contents of the current dir")
    >>> t1.action = Action("ls -l")
    """
    # TODO: Enable Task support for multiple actions.

    # TODO: make Task print instructions with what to do next, starting
    # from Task("do smth")
    # Eg:
    # >>> t1 = Task("list contents of current dir")
    # 'Define an action with "t1.action = Action("shell cmd"):'
    # >>> t1.action = Action("ls -l")
    # 'Define the python alternative to the shell action with
    # t1.action.python_cmd = "your_python_cmd": '
    def __init__(self, name):
        self.name = name
        self._action = None

    def __repr__(self):
        return ('Task("%s")' % self.name)

    @property
    def action(self):
        """Emulates a shell cmd using python specific cmds.
        This is the getter."""

        if self._action is None:
            print("No action defined!")
        else:
            return self._action

    @action.setter
    def action(self, value):
        if isinstance(value, Action):
            self._action = value
        else:
            raise TypeError("This is not a valid action. It must be an Action "
                            "or a subclass of Action object.")

    @action.deleter
    def del_action(self):
        del self._action
#    action = property(get_action, set_action, del_action, "Emulates a shell "
#                      "cmd using python specific cmds.")


class Action(object):
    """Implements the python equivalent of a shell cmd.
    shell_cmd - holds the form of the actual shell cmd.
    python_cmd - this is a python implementation of the shell_cmd.

    Initialization:
    >>> a = Action('ls -l')

    Usage:
    >>> a.python_cmd = 'sh.ls("-l")'    # using 'sh' module implementation
    >>> out = a.run_python_cmd()        # OR
    >>> out = a.get_output()
    """

    def __init__(self, cmd):
        self.shell_cmd = str(cmd)
        self._python_cmd = None
        # store the output got from running the python cmd:
        self._output = None
        #self._info_extractor = InfoExtractor()

    def __str__(self):
        return ("Action: %s" % self.shell_cmd)

    def __repr__(self):
        return ('Action("%s")' % self.shell_cmd)

    # TODO: this is a sample ToDo for tasklist vim addon, activate with \t

    def _set_python_cmd(self, cmd):
        self._python_cmd = str(cmd)

    def _get_python_cmd(self):
        return self._python_cmd

    python_cmd = property(_get_python_cmd, _set_python_cmd)

    def run_python_cmd(self):
        "Runs the string form of the python_cmd."
        if self.python_cmd is None:
            print("You need to define a python command.")
        else:
            self._output = eval(self.python_cmd)
            # if using 'sh' pypi module, .stdout is the text stream used by
            # print():
            self._output = self._output.stdout
            return self._output

    def get_output(self):
        """Returns the last output of .run_python_cmd()."""
        if self._output is None:
            self.run_python_cmd()
        return self._output


class InfoExtractor(object):
    """Used to extract relevant info using regex's.

    Usage:
    >>> i = InfoExtractor('get jails')
    >>> i.test_sample = "This is a test string."
    >>> i.pattern = re.compile(r'test', re.I)
    >>> i.test_pattern()
    >>> i.match      # doctest: +ELLIPSIS
    <_sre.SRE_Match object at ...>
    >>> i.search('This is the actual data to be browsed.')
    no match found
    >>> i.match
    """

    def __init__(self, name):
        self._name = name
        self._test_sample = None
        self.pattern = None
        self.match = None

    def __repr__(self):
        return ("InfoExtractor('%s')" % self.name)

    def _get_name(self):
        """Relevant name of the object."""
        return self._name

    # define a read-only attribute
    name = property(_get_name)

    @property
    def test_sample(self):
        return self._test_sample

    @test_sample.setter
    def test_sample(self, value):
        self._test_sample = value

    def test_pattern(self):
        if self.pattern and self.test_sample:
            txt = self.test_sample
            self.search(txt)
        else:
            print("pattern and/or test_sample not defined!")

    def search(self, txt):
        if self.pattern:
            self.match = re.search(self.pattern, txt)
            if not self.match:
                print("no match found")
        else:
            print("pattern not defined!")


if __name__ == '__main__':
    # test the docstrings:
    import doctest
    doctest.testmod()

    task_1 = Task("Get the number of fail2ban enabled jails")
    task_1.action = Action(cmd="sudo fail2ban-client status")

    # another form of `with sh.sudo:...` context:
    task_1.action.python_cmd = 'sudo("/usr/local/bin/fail2ban-client", "status")'
    task_1.action.ie = InfoExtractor("get jails")
    task_1.action.ie.test_sample = " |- Number of jails:  7"
    task_1.action.ie.pattern = re.compile(r'Number of.*:\s+(?P<jails>\d+)', re.I)

    task_1.action.ie.test_pattern()
    if not task_1.action.ie.match:
        print("pattern not good or test sample not good. Exiting...")
        sys.exit()

    task_1.action.ie.search(task_1.action.run_python_cmd())
    if not task_1.action.ie.match:
        print('nothing found. You might need to rewrite the search pattern.')
        print('Exiting...')
        sys.exit()

    jails = task_1.action.ie.match.group("jails")
    print("Jails loaded: %s" % jails)

    task_2 = Task("Get the number of netfilter/iptables fail2ban loaded chains")
    task_2.action = Action(cmd='sudo iptables -L --line-numbers | '
                           'grep "fail2ban-.*\([1-9][0-9]\? references\)"')
    cmd = ('sh.grep(sudo("/sbin/iptables", "-L", "--line-numbers"),'
                    'r"fail2ban-.*\([1-9][0-9]\? references\)")')
    task_2.action.python_cmd = cmd

    task_2.action.ie = InfoExtractor("get loaded chains")
    task_2.action.ie.test_sample = ("Chain fail2ban-BadBots (1 references)\n"
                                    "Chain fail2ban-NoProxy (1 references)\n"
                                    "Chain fail2ban-NoScript (1 references)\n")
    task_2.action.ie.pattern = re.compile(r"fail2ban-.*\([1-9][0-9]? references\)", re.I)
    match = re.findall(task_2.action.ie.pattern, task_2.action.ie.test_sample)

    # DEBUG #
#    if not match:
#        print("Task 2 test sample: nothing found")
#        print('Exiting...')
#        sys.exit()
#    elif len(task_2.action.ie.test_sample.split("\n")) - 1 == len(match):
#        print("Task 2 test sample: OK")
#    else:
#        print("Regex pattern is not good.")
    ### end debug ###

    # TODO: implement an InfoExtractor findall() method, that can be also
    # called by .test_pattern(flag=findall), for example
    match = re.findall(task_2.action.ie.pattern, task_2.action.run_python_cmd())
    if not match:
        print('nothing found. You might need to rewrite the search pattern.')
        print('Exiting...')
        sys.exit()
    chains = len(match)

    if int(jails) == chains:
        print("Fail2ban status: OK.\n"
              "All loaded jails have corresponding netfilter chains.\n")
    else:
        print("Fail2ban status: WARNING\n"
              "Not all loaded jails have corresponding netfilter chains.\n")

#if __name__ == '__main__':
    # test the docstrings:
    #import doctest
    #doctest.testmod()

    #f2b_status = task_1.action.run_python_cmd()

    # Implement: sudo fail2ban-client status
    #f2b_status = sudo("/usr/local/bin/fail2ban-client", "status")

    #f2b_status = f2b_status.stdout        # .stdout is a text stream used by print

    # Try to match: " |- Number of jails:  7"
    #pattern = re.compile(r"""
    #    Number of.*:
    #    \s+               # empty space in front of number of jails
    #    (?P<jails>\d+)    # named group with no of jails""", re.VERBOSE | re.I)
    #pattern = re.compile(r'Number of.*:\s+(?P<jails>\d+)', re.I)
    #match = re.search(pattern, f2b_status)
    #no_jails = match.group("jails")

    #print(no_jails)

    # look for fail2ban jails in netfilter tables to check if all loaded
    # jails have iptables chains too
    #rules = sh.grep(sudo("/sbin/iptables", "-L", "--line-numbers"),
    #                r"fail2ban-.*\([1-9][0-9]\? references\)")

    #rules = sh.grep(r"fail2ban-.*\([1-9][0-9]\? references\)", "good_results.txt")

    #rules = sh.grep(r"fail2ban-.*\([1-9][0-9]\? references\)", "bad_results_1.txt")
    #rules = sh.grep(r"fail2ban-.*\([1-9][0-9]\? references\)", "bad_results_2.txt")

    #print(rules)
    #loaded_jails = rules.stdout.strip().split("\n")
    #no_loaded_jails = len(loaded_jails)
    #print(loaded_jails)
    #print(no_loaded_jails)
    #if int(jails) == no_loaded_jails:
#        print("Fail2ban status: OK.\n"
#              "All loaded jails have corresponding netfilter chains.\n")
#    else:
#        print("Fail2ban status: WARNING\n"
#              "Not all loaded jails have corresponding netfilter chains.\n")
