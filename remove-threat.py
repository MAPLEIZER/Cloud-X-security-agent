#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break


    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):

    # build and send message with keys
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    # write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret

def main(argv):
    write_debug_file(argv[0], "Started")

    # Check for dry run mode
    dry_run = '--dry-run' in argv
    if dry_run:
        write_debug_file(argv[0], "Dry run mode enabled. No files will be deleted.")

    # Define safe directories for file removal
    # Using environment variables for flexibility
    safe_dirs = [
        os.path.expandvars("%USERPROFILE%\\Downloads"),
        os.path.expandvars("%TEMP%")
    ]

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        # Safely get the alert dictionary
        alert = msg.alert.get("parameters", {}).get("alert", {})
        if not alert:
            write_debug_file(argv[0], "Alert data is missing or malformed.")
            sys.exit(OS_INVALID)

        rule_id = alert.get("rule", {}).get("id")
        if not rule_id:
            write_debug_file(argv[0], "Rule ID is missing from alert.")
            sys.exit(OS_INVALID)

        keys = [rule_id]
        action = send_keys_and_check_message(argv, keys)

        # if necessary, abort execution
        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted by Wazuh manager.")
            else:
                write_debug_file(argv[0], "Invalid command received from Wazuh manager.")
            sys.exit(OS_SUCCESS if action == ABORT_COMMAND else OS_INVALID)

        # Safely get the file path from the alert
        file_path = alert.get("data", {}).get("virustotal", {}).get("source", {}).get("file")

        if not file_path:
            write_debug_file(argv[0], "File path not found in VirusTotal alert data.")
            sys.exit(OS_INVALID)

        # CRITICAL: Path validation
        abs_file_path = os.path.abspath(file_path)
        is_safe = any(abs_file_path.startswith(os.path.abspath(safe_dir)) for safe_dir in safe_dirs)

        if not is_safe:
            write_debug_file(argv[0], f"SECURITY ALERT: Attempt to delete file '{abs_file_path}' outside of safe directories was blocked.")
            sys.exit(OS_INVALID)

        try:
            if os.path.exists(abs_file_path):
                if dry_run:
                    write_debug_file(argv[0], f"[DRY RUN] Would have removed threat: {abs_file_path}")
                else:
                    os.remove(abs_file_path)
                    write_debug_file(argv[0], f"Successfully removed threat: {abs_file_path}")
            else:
                write_debug_file(argv[0], f"File not found, could not remove: {abs_file_path}")
        except OSError as e:
            write_debug_file(argv[0], f"Error removing threat '{abs_file_path}': {e}")
            sys.exit(OS_INVALID)

    else:
        write_debug_file(argv[0], f"Invalid command '{msg.command}'; expected ADD_COMMAND.")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)