#!/usr/local/bin/pythonbrew-python27-system
import shlex
import subprocess
import tempfile
import argparse
import os
import glob
import sys
import re
import fcntl

XTABLES_MULTI = '/usr/local/sbin/xtables-multi'
TABLES = ["filter", "nat", "raw", "mangle"]

CUSTOM_DIR = "/etc/iptables.d"
CUSTOM_NAME_PATTERN = r'[\-\w]+'

LOCK_FILE = "/var/run/iptables.lock"
_LOCK_FILE = None


def ensure_single_process():
    global _LOCK_FILE, LOCK_FILE
    _LOCK_FILE = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(_LOCK_FILE, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        sys.stderr.write("Another process is already running. Aborting." + os.linesep)
        sys.exit(1)


def get_args():
    parser = argparse.ArgumentParser(description="IPTABLES HELPER")
    parser.add_argument("-t", "--table", type=str, help="tables(default: {})".format(TABLES))
    parser.add_argument("-c", "--chain", type=str, default=None, help="Specific chain for list rules")
    mex_group = parser.add_mutually_exclusive_group()
    mex_group.add_argument("-l", "--list-rules", dest="list_rules", action="store_true", help="show iptables")
    mex_group.add_argument("-r", "--restore", action="store_true", help="restore iptables")
    args = parser.parse_args()

    return args


def get_tmp_file(prefix):
    tmp_file = tempfile.NamedTemporaryFile("w+b", prefix=prefix, dir='/tmp')
    return tmp_file


def get_custom_files():
    """
    Get custom files with custom rules
    :return:
    :rtype: list
    """
    if not os.path.isdir(CUSTOM_DIR):
        return []

    custom_files = glob.glob(CUSTOM_DIR + "/*.ipt")

    valid_files = []
    for path in custom_files:
        name = os.path.basename(path)
        if re.match(r'^{}\.ipt$'.format(CUSTOM_NAME_PATTERN), name):
            valid_files.append(path)
        else:
            sys.stderr.write("WARNING: invalid file name: {}".format(path) + os.linesep)

    return valid_files


def restore_custom_files(tables):
    """
    Restore rules from custom files
    :param tables:
    :param list custom_files: custom files with rules
    :return:
    """
    restore_cmd = [XTABLES_MULTI, 'iptables-restore', '--noflush']
    custom_files = get_custom_files()

    # prepare custom rules
    custom_rules = {}
    for filepath in custom_files:
        rule_name = os.path.basename(filepath).split(".")[0]
        rule_comment = "-m comment --comment CUSTOMRULE_{}".format(rule_name)

        with open(filepath, "r+") as f:
            rules = [i.rstrip() for i in f.readlines()]

        rules = prepare_rules(rules, rule_comment)

        custom_rules[rule_name] = {
            'comment': rule_comment,
            'rules': rules,
            'path': filepath,
        }

    # apply custom rules
    failed_files = []
    for rule_name, data in custom_rules.items():
        tmp_file = get_tmp_file(rule_name)

        with open(tmp_file.name, "w+b") as f:
            for rule in data['rules']:
                f.write(rule + os.linesep)
            try:
                # test new rules
                f.seek(0)
                subprocess.check_output(restore_cmd + ['--test'], stdin=f, stderr=subprocess.PIPE)

                # apply new rules
                f.seek(0)
                subprocess.check_output(restore_cmd, stdin=f, stderr=subprocess.PIPE)
            except Exception as e:
                sys.stderr.write("- unable to restore: {} ({})".format(rule_name, e) + os.linesep)
                failed_files.append(data['path'])

    if failed_files:
        sys.stderr.write("FAILED CUSTOM FILES: {}".format(failed_files) + os.linesep)
        sys.exit(1)
    else:
        print("RESTORE CUSTOM RULES: SUCCESS")


def get_table_rules(table, ipt_rules):
    """
    Extract table specific rules from given rules
    :param str table:
    :param list ipt_rules:
    :return: table specific rules
    :rtype: list
    """
    start = 0
    table_rules = []

    for line in ipt_rules:
        if is_comment(line):
            continue

        if start == 0:
            if is_table(line) and table in line:
                start = 1
                table_rules.append(line)
                continue

        if start == 1:
            if is_commit(line):
                table_rules.append(line)
                break

            table_rules.append(line)

    return table_rules


def is_base_rule(line):
    """
    Match base rule by comment
    :param basestring line:
    :return:
    """
    # match --comment BASERULE
    re_str = r'\s+--comment\s+BASERULE'
    re_str += r'(?:\s+|\s*$)'  # end of string or spaces

    m = re.search(re_str, line)
    return m


def is_custom_rule(line, name=None):
    """
    Match custom rule by comment
    :param basestring line:
    :param basestring name:
    :return:
    """
    # match --comment CUSTOMRULE_<some_name_here>
    re_str = r'\s+--comment\s+CUSTOMRULE'
    if name is None:
        re_str += r'(?:_({}))?'.format(CUSTOM_NAME_PATTERN)  # match _[a-z0-9_-] symbols
    else:
        re_str += r'_({})'.format(re.escape(name))
    re_str += r'(?:\s+|\s*$)'  # end of string or spaces

    m = re.search(re_str, line)
    return m


def remove_comment(line):
    """match --comment <WORDS>
    or match --comment '<WORDS>'
    or match --comment "<WORDS>"
    and replace it with ""
    """
    comment_patterns = [
        r"""\s+--comment\s+(?:\S+|'[^']+'|"[^"]+")(?:\s+|\s*$)""",
        r'\s+\-m\s+comment(?:\s+|\s*$)']

    for p in comment_patterns:
        line = re.sub(p, "", line)

    return line


def is_chain(line):
    return line.startswith(":")


def is_table(line):
    return line.startswith("*")


def is_comment(line):
    return line.startswith("#")


def is_commit(line):
    return "COMMIT" in line


def is_blank(line):
    return not line.strip()


def get_chain_name(line):
    return line.split()[0].lstrip(':')


def get_runtime_rules():
    """
    Return iptables-save output as lines
    :rtype: list
    """
    tmp_iptables_file = get_tmp_file('iptables-tmp')
    with open(tmp_iptables_file.name, "w+") as f:
        cmd = [XTABLES_MULTI, 'iptables-save']
        try:
            subprocess.check_call(cmd, stdout=f)
        except Exception as e:
            sys.stderr.write("Cannot get runtime iptables rules: {}".format(e) + os.linesep)
            sys.exit(1)

    rules = [i.rstrip() for i in tmp_iptables_file.readlines()]
    return rules


def get_base_rules():
    """
    Get base rules from /etc/iptables
    :rtype: list
    """
    iptables_path = "/etc/iptables"

    with open(iptables_path, "r+") as f:
        rules = [i.rstrip() for i in f.readlines()]

    rules = prepare_rules(rules, "-m comment --comment BASERULE")
    return rules


def merge_rules(base_rules, runtime_rules, table):
    """
    Merge runtime rules with base rules for given table
    :param list base_rules:
    :param list runtime_rules:
    :param str table:
    :return: merged rules
    :rtype: list
    """
    merged_rules = []
    chains = []

    merged_rules.append("*{}".format(table))

    # filter runtime rules to skip managed ones
    for line in runtime_rules:
        if is_base_rule(line):
            continue
        elif is_custom_rule(line):
            continue
        elif is_commit(line):
            continue
        elif is_table(line):
            continue
        elif is_chain(line):
            chains.append(get_chain_name(line))
            merged_rules.append(line)
        else:
            merged_rules.append(line)

    # add base rules
    for line in base_rules:
        if is_chain(line):
            chain_name = get_chain_name(line)
            if not chain_name in chains:
                merged_rules.append(line)
        elif is_base_rule(line):
            merged_rules.append(line)
        elif is_commit(line):
            continue

    merged_rules.append('COMMIT')

    return merged_rules


def is_rule(line):
    if is_chain(line):
        return False
    elif is_table(line):
        return False
    elif is_commit(line):
        return False
    elif is_comment(line):
        return False
    elif is_blank(line):
        return False

    return True


def prepare_rules(rules, comment):
    """
    Replace comment in rules with given one
    :param list rules: iptables rules
    :param str comment: new comment
    :return:
    """
    prepared_rules = []
    for rule in rules:
        if is_rule(rule):
            rule = remove_comment(rule)
            rule = '{} {}'.format(rule, comment)
        prepared_rules.append(rule)
    return prepared_rules


def restore_rules(tables):
    """
    Restore all rules from files
    :param tables: iptables table names
    :return:
    """
    ensure_single_process()

    restore_base_file(tables)
    restore_custom_files(tables)


def restore_base_file(tables):
    """
    Restore rules from base file (drops all custom rules)
    :param tables:
    :return:
    """
    runtime_rules = get_runtime_rules()
    base_rules = get_base_rules()

    tmp_file = get_tmp_file("tmp-ipt-restore")

    with open(tmp_file.name, "w+b") as f:
        for table in tables:
            table_base_rules = get_table_rules(table, base_rules)
            tables_runtime_rules = get_table_rules(table, runtime_rules)
            for rule in merge_rules(table_base_rules, tables_runtime_rules, table):
                f.write(rule + os.linesep)

        f.seek(0)
        cmd = [XTABLES_MULTI, 'iptables-restore']
        retcode = subprocess.call(cmd, stdin=f)

    if retcode == 0:
        print("RESTORE BASE RULES: SUCCESS")


def show_rules(table):
    """
    Display runtime rules
    :param table:
    :return:
    """
    extra_args = []

    if table:
        extra_args = ["-t", table]

    cmd = [XTABLES_MULTI, 'iptables-save']
    subprocess.call(cmd + extra_args)


def remove_runtime_rule(table, rule):
    """
    Remove given rule from runtime
    :param basestring table:
    :param basestring rule:
    :return:
    """
    cmd = [XTABLES_MULTI, 'iptables', '-t', table, '-D']

    tokens = shlex.split(rule)
    assert(tokens[0].startswith('-'))

    subprocess.check_call(cmd + tokens[1:])


def show_rules_list(table, chain):
    extra_args = []

    if chain:
        extra_args.append(chain)

    if table:
        extra_args.extend(["-t", table])

    cmd = [XTABLES_MULTI, 'iptables', '--line-numbers', '-v', '-n', '-L']
    subprocess.call(cmd + extra_args)


def main():
    args = get_args()
    table = None

    if args.table and args.table in TABLES:
        table = args.table

    if args.restore:
        restore_rules(TABLES)
    elif args.list_rules:
        show_rules_list(table, args.chain)
    else:
        show_rules(table)


if __name__ == '__main__':
    main()
