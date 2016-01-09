#!/usr/local/bin/pythonbrew-python27-system

import subprocess
import tempfile
import argparse
import os
import glob
import sys
import re

XTABLES_MULTI = '/usr/local/sbin/xtables-multi'
TABLES = ["filter", "nat", "raw", "mangle"]
CUSTOM_DIR = "/etc/iptables.d"


def get_args():
    parser = argparse.ArgumentParser(description="ALL HAIL IPTABLES")
    parser.add_argument("-t", "--table", type=str, help="tables(default: %s)" % TABLES)
    parser.add_argument("-c", "--chain", type=str, default=None, help="Specific chain for list rules")
    mex_group = parser.add_mutually_exclusive_group()
    mex_group.add_argument("-l", "--list-rules", dest="list_rules", action="store_true", help="show iptables")
    mex_group.add_argument("-r", "--restore", action="store_true", help="restore iptables")
    args = parser.parse_args()

    return args


def get_temp_file(t_prefix):
    t_file = tempfile.NamedTemporaryFile("w+b", prefix=t_prefix, dir='/tmp')

    return t_file


def get_custom_rules():
    if not os.path.isdir(CUSTOM_DIR):
        return []

    custom_rules = glob.glob(CUSTOM_DIR + "/*.ipt")
    return custom_rules


def restore_custom_rules(custom_rules):
    for r in custom_rules:
        with open(r, "r+") as f:
            name_f = os.path.basename(r).split(".")[0]
            data = [i.rstrip() for i in f.readlines()]
            t_file = open(get_temp_file(name_f).name, "w+b")
            p_data = prepare_data(data, " -m comment --comment CUSTOMRULE_%s" % name_f)
            for line in p_data:
                t_file.write(line + "\n")
            t_file.seek(0)
            cmd = [XTABLES_MULTI, 'iptables-restore', "-n"]
            subprocess.call(cmd, stdin=t_file)
            t_file.close()


def get_table(table, ipt_rules):
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
    line = line.split()

    return "--comment" in line and "BASERULE" in line


def is_custom_rule(line):
    # match --comment CUSTOMRULE_<some_name_here>
    m = re.search(r'\s+--comment\s+CUSTOMRULE(?:_\w+)?(?:\s+|\s*$)', line)

    return m


def remove_comments(line):
    """match --comment <WORDS>
    or match --comment '<WORDS>'
    or match --comment "<WORDS>"
    and replace it with ""
    """
    comment_patterns = [
        r"""\s+--comment\s+(?:\w+|'[^']+'|"[^"]+")(?:\s+|\s*$)""",
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


def get_curr_iptables():
    tmp_iptables_file = get_temp_file('iptables-tmp')
    with open(tmp_iptables_file.name, "w+") as f:
        cmd = [XTABLES_MULTI, 'iptables-save']
        try:
            subprocess.check_call(cmd, stdout=f)
        except Exception as e:
            print "Can't get current iptables"
            print "Error: %s" % e
            sys.exit(1)

    return tmp_iptables_file


def get_base_iptables():
    iptables_path = "/etc/iptables"

    return iptables_path


def merge_rules(ipt_table_1, ipt_table_2, table_type):
    merged_rules = []
    chains = []

    merged_rules.append("*%s" % table_type)

    for line in ipt_table_2:
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

    for line in ipt_table_1:
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


def prepare_data(data, comment):
    prepared_data = []
    for line in data:
        if is_rule(line):
            line = remove_comments(line)
            prepared_data.append(line + comment)
        else:
            prepared_data.append(line)

    return prepared_data


def restore_rules(tables):
    tmp_cur_iptables = get_curr_iptables()
    tmp_base_iptables = get_base_iptables()
    ipt_restore_tmp = get_temp_file("tmp-ipt-restore")

    with open(tmp_base_iptables, "r+") as f:
        base_ipt_data = [i.rstrip() for i in f.readlines()]

    tmp_ipt_data = [i.rstrip() for i in tmp_cur_iptables.readlines()]
    base_ipt_data = prepare_data(base_ipt_data, " -m comment --comment BASERULE")

    for t in tables:
        base_table = get_table(t, base_ipt_data)
        tmp_table = get_table(t, tmp_ipt_data)
        with open(ipt_restore_tmp.name, "a+b") as f:
            for line in merge_rules(base_table, tmp_table, t):
                f.write(line + '\n')

    with open(ipt_restore_tmp.name, "r+") as f:
        cmd = [XTABLES_MULTI, 'iptables-restore']
        retcode = subprocess.call(cmd, stdin=f)

    if retcode == 0:
        print "RESTORE BASE RULE: SUCCESS"

    custom_rules = get_custom_rules()
    if custom_rules:
        restore_custom_rules(custom_rules)


def show_rules(table):
    extra_args = []

    if table:
        extra_args = ["-t", table]

    cmd = [XTABLES_MULTI, 'iptables-save']
    subprocess.call(cmd + extra_args)


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
