#!/usr/bin/env python3

import argparse
import csv
import gzip
import json
import logging
import os
import re

global LOGGER
LOGGER = logging.getLogger('suri')

def setup_logging(path='run.log', level='error'):
    global LOGGER
    if path == '-':
        def log_stderr(error_level):
            ''' Custom logger to stderr '''
            def error_level_logger(msg):
                print >>sys.stderr, '[LOG] %s: %s' % (error_level, msg)
            return error_level_logger

        class Logger(object):
            pass
        LOGGER = Logger()
        LOGGER.error = log_stderr('ERROR')
        LOGGER.critical = log_stderr('CRITICAL')
        LOGGER.warning = log_stderr('WARNING')
        LOGGER.info = log_stderr('INFO')
        LOGGER.debug = log_stderr('DEBUG')
    else:
        log_level = getattr(logging, level.upper())
        LOGGER.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)s [%(levelname)s]: %(message)s')
        file_handler = logging.FileHandler(path)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(log_level)
        LOGGER.addHandler(file_handler)
        LOGGER.addHandler(stream_handler)


def beautify_payload(payload):
    res = ''
    dot_count = 0
    for i in range(0, len(payload)):
        if payload[i] == '.':
            dot_count += 1
        else:
            if dot_count > 1:
                res += '.'
            res += payload[i]
            dot_count = 0

    res = res.replace('\r', '\\r').replace('\n', '\\n')
    return res


def parse_log(f, sigs, exclude):
    logs = []
    for full_line in f:
        # strip out 0x0a in case newline was not stripped correctly
        line = full_line.replace('\x0a', '').strip()
        try:
            line_data = json.loads(line)
        except ValueError as e:
            LOGGER.error('%s: %s\nLine: %s' % (e.__class__.__name__, e, line))
            continue

        sigid = str(line_data['alert']['signature_id'])
        if sigid not in sigs:
            continue

        ts = line_data['timestamp']
        src = line_data['src_ip']
        dst = line_data['dest_ip']

        payload = ''
        if 'payload_printable' in line_data:
            payload = beautify_payload(line_data['payload_printable'])

        row = f'{ts}: {src} -> {dst} -- {payload} ({sigid})'
        logs.append(row)

    return logs


def parse(path, sigs, exclude=None):
    if exclude is not None:
        re_exclude = exclude_regex(exclude)
        LOGGER.debug('Compiled exclusion regex')
    else:
        re_exclude = None

    ext = os.path.splitext(path)[-1].lower()
    if ext == '.gz':
        with gzip.open(path) as f:
            return parse_log(f, sigs, exclude)
    else:
        with open(path) as f:
            return parse_log(f, sigs, exclude)


def exclude_regex(arg):
    LOGGER.debug('Compiling exclusion regex')
    return re.compile(arg)


def write_logs(output, logs):
    with open(output, 'w') as f:
        for row in logs:
            f.write(row)
            f.write('\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('log', help='Path to eve.json log file. Can be in GZIP format, will be autodetected')
    parser.add_argument('-o', '--output', help='Output file with parsing results', default='suri.log')
    parser.add_argument('-s', '--sigids', help='Signature ID of the rule to include. Defaults to common SMB events', nargs='*', default=['2025701', '2025702', '2025703', '2025704', '2025705', '2025706', '2025707', '2025708', '2025709', '2025710', '2025711', '2025712', '2025713', '2025714', '2025715', '2025719', '2025720', '2025722', '2025723', '2025724', '2025725', '2025726'])
    parser.add_argument('-x', '--exclude', help='exclude certain rrnames based on regex. eg ^(.*\.)?mydomain(\.(com|net|org))?$')

    args = parser.parse_args()

    setup_logging()

    logs = parse(args.log, args.sigids, args.exclude)
    write_logs(args.output, logs)


if __name__ == '__main__':
    main()
