#!/usr/bin/env python3
"""
Script to display and update SNMP and Data retention Settings on NetWorker Devices and backup Policy.
This script retrieves device and policy information from NetWorker using nsradmin commands
and formats the output into tables.
Last Updated: 08/05/2025
Version: 1.8.0
Maintainer: Dayanand Kadam <dayakadam@yahoo.com>
Changes in v1.8.0:
- Added support for [PWA Exclusion list] section in the config file.
- The script now skips policy/workflow/action updates if they are found in the exclusion list.
- Updated config file for [Retention Lock Period]
Changes in v1.7.0:
- Added support for [NSR Device list] section in config file for wildcard filtering.
- Fixed 'NoneType' error when running display commands without a config file.
- Enhanced --show-dd and --show-pol options to accept 'ALL' or '*' for displaying all entities.
Changes in v1.6.0:
- Fixed config file parsing error by separating INI parsing from custom Data Domain list parsing.
- The custom Data Domain list section in the config file is now correctly read, ignoring comments (#).
Changes in v1.5.0:
- Updated wildcard logic for -dd and -dev options to allow -dd * -dev * and -dd <list> -dev *.
- Added support for parsing a list of Data Domain systems from the config file for wildcard resolution.
- Comments (#) in the Data Domain list section of the config file are now ignored.
Changes in v1.4.0:
- Suppressed logging of nsradmin query commands when script is run in display mode.
Changes in v1.3.0:
- Added log file support, to keep logs in /var/log/nwrkr-rlock/ directory.
Changes in v1.2.0:
- Added command-line wildcard support for -dd and -dev options
- Enhanced validation logic for wildcard combinations
- Improved parameter validation and error handling
"""

import argparse
import subprocess
import sys
import re
import configparser
from typing import List, Dict, Any, Tuple
import logging
import os
from datetime import datetime # To get current date for log file name

# Global logger instance
logger = None

def setup_logging():
    """
    Configures the logger to write *only* to a daily rotating log file.
    Console output will be handled by explicit print() statements.
    Ensures the log directory exists.
    """
    global logger
    if logger is not None: # Prevent re-initialization if called multiple times
        return

    log_dir = "/var/log/nwrkr-rlock"
    try:
        os.makedirs(log_dir, exist_ok=True) # Ensure log directory exists
    except OSError as e:
        # Fallback to current directory if /var/log is not writable
        print(f"Warning: Could not create log directory '{log_dir}'. Falling back to current directory.", file=sys.stderr)
        log_dir = os.path.dirname(os.path.abspath(__file__)) or '.'

    log_filename = datetime.now().strftime(f"{log_dir}/nwrkr-rlock-%Y%m%d.log")
    
    # Create a new logger instance
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO) # Set the minimum logging level

    # Create file handler which logs even debug messages
    fh = logging.FileHandler(log_filename)
    fh.setLevel(logging.INFO)

    # Create formatter and add it to the handler
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    fh.setFormatter(formatter)

    # Add the handler to the logger
    if not logger.handlers:
        logger.addHandler(fh)

class NetWorkerConfig:
    """Configuration class to hold all configuration values."""
    def __init__(self):
        # Initialize with None values - will be set from config file
        self.snmp_community_string = None
        self.management_host = None
        self.management_user = None
        self.management_password = None
        self.dd_retention_lock_mode = None
        self.retention_lock_times = {}
        self.apply_dd_retention_lock = None
        self.nsr_device_name = None
        # New fields for wildcard support
        self.data_domain_system = None  # Can be "*", single name, or comma-separated list
        self.nsr_device_list = None     # Can be "*", single name, or comma-separated list
        self.data_domain_name = None    # Used for NSR device filtering
        self.pwa_exclusions = []        # New field to store Policy/Workflow/Action exclusions
        self.data_domain_wildcard_list = [] # List of DDs from config file for '*' or 'ALL'
        self.nsr_device_wildcard_list = [] # List of NSR Devices from config file for '*' or 'ALL'


def run_nsradmin_command(command: str, server: str, is_update_command: bool = False, is_display_mode: bool = False) -> str:
    """
    Executes an nsradmin command and returns the output.
    Raises an exception on command failure.
    is_update_command is used to control logging behavior.
    is_display_mode is used to suppress logging of query commands in display mode.
    """
    option_string = "option Resource ID;hidden;showall" if not is_update_command else "option Resource ID;hidden"
    full_cmd = f"printf \"{option_string}\\n{command}\\n\" | nsradmin -s {server}"
    
    # Only log command execution if it's an update, or if not in display mode for queries
    if logger and (is_update_command or not is_display_mode):
        log_cmd = full_cmd.replace('password: *******;', 'password: <hidden>;') # Mask password for logging
        logger.info(f"Executing NetWorker command: {log_cmd}")

    try:
        # Changed text=True to universal_newlines=True for broader Python compatibility
        result = subprocess.run(full_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        output = result.stdout
        error_output = result.stderr # Capture stderr
        
        # Log successful execution output for update commands
        if logger and is_update_command:
            logger.info(f"NetWorker update command successful. Output:\n{output}\nStderr:\n{error_output}")
        # Otherwise, log info if there is output, but not the verbose query command itself, and not in display mode
        elif logger and not is_display_mode:
            logger.info(f"NetWorker query command successful.")

        # Combine stdout and stderr for update commands for robust checking
        combined_output = output
        if is_update_command and error_output:
            combined_output = output + "\n" + error_output

        # Check for explicit failure messages in combined output for update commands
        # nsradmin might return 0 exit code but print "update failed" to stdout
        if is_update_command and ("update failed" in combined_output.lower() or "invalid user name or password" in combined_output.lower()):
            # If we detect a failure message, return a specific string indicating internal failure
            return "UPDATE_FAILED_INTERNAL_ERROR:" + combined_output # Prefix to distinguish from normal output

        # Filter out nsradmin preamble and other non-data lines for actual parsing
        filtered_lines = []
        for line in output.splitlines(): # Filter only stdout for normal data parsing
            if not (
                line.startswith("NetWorker administration program.") or
                line.startswith("Use the \"help\" command for help, \"visual\" for full-screen mode.") or
                line.startswith("nsradmin>") or
                line.startswith("Hidden display option turned on") or
                line.startswith("Resource ID display option turned on") or
                line.startswith("Showall display option turned on") or
                line.startswith("Display options:") or
                line.startswith("        Dynamic:") or
                line.startswith("        Hidden:") or
                line.startswith("        Raw I18N:") or
                line.startswith("        Resource ID:") or
                line.startswith("        Regexp:") or
                line.startswith("        Showall:") or
                line.strip().startswith("Update?")
            ):
                filtered_lines.append(line)
        return "\n".join(filtered_lines).strip()

    except subprocess.CalledProcessError as e:
        error_msg = f"NetWorker command failed with exit code {e.returncode}. Stderr: {e.stderr}"
        if logger:
            logger.error(error_msg)
        # For non-zero exit codes, still raise a RuntimeError with stderr for main() to catch
        raise RuntimeError(error_msg)
    except subprocess.TimeoutExpired as e:
        error_msg = f"NetWorker command timed out after {e.timeout} seconds."
        if logger:
            logger.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as e:
        error_msg = f"An unexpected error occurred while running nsradmin: {e}"
        if logger:
            logger.error(error_msg)
        raise RuntimeError(error_msg)

def parse_nsradmin_blocks(nsradmin_output: str) -> List[Dict[str, str]]:
    """Parses nsradmin output into a list of dictionaries, one per resource block."""
    parsed_resources = []
    lines = nsradmin_output.splitlines()
    current_resource = {}
    last_key = None # Track the last key successfully parsed to handle continuations

    i = 0
    while i < len(lines):
        line = lines[i]

        if not line.strip(): # Empty line (or line with only whitespace) signals end of a resource block
            if current_resource:
                parsed_resources.append(current_resource)
                current_resource = {}
                last_key = None # Reset last_key for a new block
            i += 1
            continue

        match = re.match(r"^\s*(\w[\w ]*?):\s*(.*?)(?:;|$)", line)
        
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()

            while value.endswith('\\') and i + 1 < len(lines):
                i += 1
                next_line = lines[i].strip()
                value = value[:-1] + next_line
            
            value = value.rstrip(';').strip('"').strip()
            current_resource[key] = value
            last_key = key
        elif last_key and line.strip():
            current_resource[last_key] += " " + line.strip().rstrip(';').strip('"')
        
        i += 1

    if current_resource: # Add the last parsed resource if any
        parsed_resources.append(current_resource)

    return parsed_resources

def parse_comma_separated_list(value: str) -> List[str]:
    """Parse a comma-separated string into a list of trimmed values."""
    if not value or value.strip() == "":
        return []
    return [item.strip() for item in value.split(',') if item.strip()]

def should_apply_dd_config_from_cmdline(dd_name: str, cmdline_dd_target: str, config: NetWorkerConfig) -> bool:
    """
    Determine if Data Domain configuration should be applied based on command-line argument.
    Returns True if:
    - cmdline_dd_target is "*" or "ALL" (apply to all DDs in config.data_domain_wildcard_list, or truly all if list is empty)
    - dd_name matches cmdline_dd_target exactly
    - dd_name is in the comma-separated list of cmdline_dd_target
    """
    if not cmdline_dd_target:
        return False
    
    cmdline_dd_target_upper = cmdline_dd_target.strip().upper()

    if cmdline_dd_target_upper in ["*", "ALL"]:
        # If '*' or 'ALL' is used, check against the list from the config file
        if config and config.data_domain_wildcard_list:
            return dd_name in config.data_domain_wildcard_list
        else:
            # If config list is empty, then '*' or 'ALL' truly means all discovered DDs
            return True
    
    # Otherwise, it's a specific name or comma-separated list
    target_systems = parse_comma_separated_list(cmdline_dd_target)
    return dd_name in target_systems

def should_apply_device_config_from_cmdline(device_name: str, associated_dd_name: str, cmdline_dev_target: str, cmdline_dd_target: str, config: NetWorkerConfig) -> bool:
    """
    Determine if NSR Device configuration should be applied based on command-line arguments.
    Returns True if:
    - cmdline_dev_target is "*" or "ALL" AND the device's associated DD matches cmdline_dd_target (specific DD only)
    - device_name matches cmdline_dev_target exactly
    - device_name is in the comma-separated list of cmdline_dev_target
    """
    if not cmdline_dev_target:
        return False
    
    cmdline_dev_target_upper = cmdline_dev_target.strip().upper()
    cmdline_dd_target_upper = cmdline_dd_target.strip().upper() if cmdline_dd_target else ""

    if cmdline_dev_target_upper in ["*", "ALL"]:
        if cmdline_dd_target_upper in ["*", "ALL"]:
            # Case: -dd * -dev * (all devices on all DDs specified in config or discovered)
            if config and config.nsr_device_wildcard_list: # If NSR device list is provided, filter by it
                return device_name in config.nsr_device_wildcard_list
            elif config and config.data_domain_wildcard_list: # If DD list is provided, filter devices by those DDs
                return associated_dd_name in config.data_domain_wildcard_list
            else:
                return True # All devices on all discovered DDs
        else:
            # Case: -dd <specific_dd> or <dd_list> -dev * (all devices on specific DDs)
            # Here, cmdline_dd_target is a specific name or list, so use should_apply_dd_config_from_cmdline
            return should_apply_dd_config_from_cmdline(associated_dd_name, cmdline_dd_target, config)
    
    # Otherwise, it's a specific name or comma-separated list
    target_devices = parse_comma_separated_list(cmdline_dev_target)
    return device_name in target_devices

def build_dd_device_mapping(dds: List[Dict[str, str]], devices: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Builds a mapping of Data Domains to their associated NetWorker devices."""
    result = []

    # Map Data Domains by their 'name' for quick lookup
    dd_map = {dd.get('name', '').strip(): dd for dd in dds if dd.get('name')}

    for dev in devices:
        # Extract Data Domain Name from 'device access information'
        dd_name_from_device = "N/A"
        device_access_info = dev.get('device access information', '')
        
        dd_access_match = re.match(r"([^:]+):/.*", device_access_info)
        if dd_access_match:
            dd_name_from_device = dd_access_match.group(1).strip()
        else:
            # Dynamically identify the Data Domain name from device 'name' if not in 'device access information'
            # This checks if any known Data Domain name (from the 'dds' list) is part of the device name.
            device_full_name = dev.get('name', '')
            found_dd_name = None
            for known_dd_name in dd_map.keys():
                if known_dd_name in device_full_name:
                    found_dd_name = known_dd_name
                    break
            if found_dd_name:
                dd_name_from_device = found_dd_name
            else:
                dd_name_from_device = "N/A" # If no DD name can be determined, set to N/A


        associated_dd = dd_map.get(dd_name_from_device)

        dd_ret_lock_mode = dev.get('DD Retention Lock Mode', 'N/A') or 'N/A'
        dd_ret_min = dev.get('DD Retention Period Min', 'N/A') or 'N/A'
        dd_ret_max = dev.get('DD Retention Period Max', 'N/A') or 'N/A'

        entry = {
            "DD Name": dd_name_from_device,
            "Device name": dev.get('name', 'N/A') or 'N/A',
            "DD Ret lock mode": dd_ret_lock_mode,
            "DD Ret min": dd_ret_min,
            "DD Ret Max": dd_ret_max,
        }

        if associated_dd:
            entry.update({
                "mgmt host": associated_dd.get('management host', 'N/A') or 'N/A',
                "mgmt user": associated_dd.get('management user', 'N/A') or 'N/A',
                "mgmt passwd": "*******" if associated_dd.get('management password') else 'N/A',
                "mgmt port": associated_dd.get('management port', 'N/A') or 'N/A',
                "SNMP Comm.": associated_dd.get('SNMP community string', 'N/A') or 'N/A',
            })
        else:
            entry.update({
                "mgmt host": 'N/A', "mgmt user": 'N/A', "mgmt passwd": 'N/A',
                "mgmt port": 'N/A', "SNMP Comm.": 'N/A',
            })
        result.append(entry)
    return result


def get_all_policy_action_details(server: str, is_display_mode: bool = False) -> List[Dict[str, str]]:
    """Retrieves and parses details for all NSR protection policy actions."""
    command = ". type: NSR protection policy action\np"
    output = run_nsradmin_command(command, server, is_display_mode=is_display_mode)

    all_actions_data = parse_nsradmin_blocks(output)

    formatted_actions = []
    for action in all_actions_data:
        formatted_actions.append({
            'Policy Name': (action.get('policy name', 'N/A') or 'N/A').strip(), # Ensure stripped
            'Workflow Name': (action.get('Workflow name', 'N/A') or 'N/A').strip(), # Ensure stripped
            'Action Name': (action.get('name', 'N/A') or 'N/A').strip(), # Ensure stripped
            'Dest Storage Node': action.get('Destination storage node', 'N/A') or 'N/A',
            'Dest Pool': action.get('Destination pool', 'N/A') or 'N/A',
            'Retention': action.get('Retention', 'N/A') or 'N/A',
            'DD Ret Apply?': action.get('Apply DD retention lock', 'N/A') or 'N/A',
            'DD Ret Lock Time': action.get('DD retention lock time', 'N/A') or 'N/A'
        })

    formatted_actions.sort(key=lambda x: (x['Policy Name'], x['Workflow Name'], x['Action Name']))

    return formatted_actions


def check_and_apply_datadomain_config(server: str, dd_name: str, current_config: Dict[str, str], config: NetWorkerConfig, dry_run: bool = False) -> Dict[str, Tuple[str, str]]:
    """
    Checks if DD management settings are in the desired state.
    If dry_run is True, it returns discrepancies without applying.
    If dry_run is False, it applies changes and prints status.
    Returns a dictionary of (current_value, desired_value) for discrepancies, or empty dict if no changes.
    """
    discrepancies = {}

    current_snmp = current_config.get('SNMP community string')
    if current_snmp != config.snmp_community_string:
        discrepancies['SNMP community string'] = (current_snmp, config.snmp_community_string)

    current_mgmt_host = current_config.get('management host')
    if current_mgmt_host != config.management_host:
        discrepancies['management host'] = (current_mgmt_host, config.management_host)

    current_mgmt_user = current_config.get('management user')
    if current_mgmt_user != config.management_user:
        discrepancies['management user'] = (current_mgmt_user, config.management_user)

    if discrepancies.get('management host') or discrepancies.get('management user') or discrepancies.get('SNMP community string'):
        discrepancies['management password'] = ("<unknown current>", config.management_password)


    if dry_run:
        return discrepancies

    if not discrepancies:
        print(f"  Configuration for {dd_name} is already in the desired state. No changes applied.")
        return {}

    print(f"  Applying updates for Data Domain: {dd_name}")
    for key, (current_val, desired_val) in discrepancies.items():
        if key == 'management password':
            print(f"    - {key}: {current_val} -> ******** (new password will be set)")
        else:
            print(f"    - {key}: '{current_val}' -> '{desired_val}'")

    success_snmp = True
    success_mgmt = True

    if 'SNMP community string' in discrepancies:
        snmp_update_cmd = (f". type: NSR Data Domain; name: \"{dd_name}\"\n" # Added quotes for dd_name
                           f"update SNMP community string: \"{config.snmp_community_string}\"\n" # Added quotes for value
                           f"y\nquit")
        snmp_output = run_nsradmin_command(snmp_update_cmd, server, is_update_command=True)
        # Check for the specific failure prefix or "Update successful"
        if snmp_output.startswith("UPDATE_FAILED_INTERNAL_ERROR:"):
            error_details = snmp_output[len("UPDATE_FAILED_INTERNAL_ERROR:"):]
            print(f"    SNMP community string update failed. Details: {error_details}", file=sys.stderr)
            success_snmp = False
        elif "Update successful" in snmp_output:
            print(f"    SNMP community string update successful.")
        else:
            print(f"    SNMP community string update returned unexpected output. Output:\n{snmp_output}", file=sys.stderr)
            success_snmp = False

    if 'management host' in discrepancies or 'management user' in discrepancies or 'management password' in discrepancies:
        mgmt_update_cmd = (f". type: NSR Data Domain; name: \"{dd_name}\"\n" # Added quotes for dd_name
                           f"update management host: \"{config.management_host}\"; " # Added quotes for value
                           f"management user: \"{config.management_user}\"; " # Added quotes for value
                           f"management password: \"{config.management_password}\"\n" # Added quotes for value
                           f"y\nquit")
        mgmt_output = run_nsradmin_command(mgmt_update_cmd, server, is_update_command=True)
        # Check for the specific failure prefix or "Update successful"
        if mgmt_output.startswith("UPDATE_FAILED_INTERNAL_ERROR:"):
            error_details = mgmt_output[len("UPDATE_FAILED_INTERNAL_ERROR:"):]
            print(f"    Management details update failed. Details: {error_details}", file=sys.stderr)
            success_mgmt = False
        elif "Update successful" in mgmt_output:
            print(f"    Management details update successful.")
        else:
            print(f"    Management details update returned unexpected output. Output:\n{mgmt_output}", file=sys.stderr)
            success_mgmt = False

    if success_snmp and success_mgmt:
        print(f"  Successfully applied all desired configurations for {dd_name}.")
    else:
        print(f"  Failed to apply all desired configurations for {dd_name}.", file=sys.stderr)
    
    return {}


def check_and_apply_device_retention_lock_mode(server: str, device_name: str, current_config: Dict[str, str], config: NetWorkerConfig, dry_run: bool = False) -> Dict[str, Tuple[str, str]]:
    """
    Checks if Device DD Retention Lock Mode is in the desired state.
    If dry_run is True, it returns discrepancies without applying.
    If dry_run is False, it applies changes and prints status.
    Returns a dictionary of (current_value, desired_value) for discrepancies, or empty dict if no changes.
    """
    discrepancies = {}
    current_retention_mode = current_config.get('DD Retention Lock Mode')

    if current_retention_mode != config.dd_retention_lock_mode:
        discrepancies['DD Retention Lock Mode'] = (current_retention_mode, config.dd_retention_lock_mode)

    if dry_run:
        return discrepancies

    if not discrepancies:
        print(f"  DD Retention Lock Mode for device '{device_name}' is already '{config.dd_retention_lock_mode}'. No changes applied.")
        return {}
    
    print(f"  Applying updates for device: {device_name}")
    for key, (current_val, desired_val) in discrepancies.items():
        print(f"    - {key}: '{current_val}' -> '{desired_val}'")

    update_cmd = (f". type: NSR device; name: \"{device_name}\"\n" # Added quotes for device_name
                  f"update DD Retention Lock Mode: \"{config.dd_retention_lock_mode}\"\n" # Added quotes for value
                  f"y\nquit")
    
    update_output = run_nsradmin_command(update_cmd, server, is_update_command=True)

    # Check for the specific failure prefix or "Update successful"
    if update_output.startswith("UPDATE_FAILED_INTERNAL_ERROR:"):
        error_details = update_output[len("UPDATE_FAILED_INTERNAL_ERROR:"):]
        print(f"  Failed to update DD Retention Lock Mode for device '{device_name}'. Details: {error_details}", file=sys.stderr)
    elif "Update successful" in update_output:
        print(f"  Successfully updated DD Retention Lock Mode for device '{device_name}'.")
    else:
        print(f"  NetWorker update command returned unexpected output or failed. Output:\n{update_output}", file=sys.stderr)
    
    return {}

def apply_policy_dd_retention_settings_dry_run(server: str, policy_name: str, policy_type: str, config: NetWorkerConfig) -> Tuple[bool, List[str]]:
    """
    Performs a dry run for DD retention lock settings on a policy's actions.
    Returns a tuple: (any_changes_needed: bool, dry_run_messages: List[str]).
    """
    desired_retention_time = config.retention_lock_times.get(policy_type.upper())
    if not desired_retention_time:
        # This error should ideally be caught earlier by argparse or load_config_from_file
        return False, [f"Error: Invalid policy type '{policy_type}' for dry run."]

    policy_name_cleaned_lower = policy_name.strip().lower()
    all_policy_actions = get_all_policy_action_details(server)
    
    actions_to_process = [
        action for action in all_policy_actions
        if action.get('Policy Name', '').lower() == policy_name_cleaned_lower and action.get('Action Name') != 'Clone'
    ]

    if not actions_to_process:
        return False, [f"No non-Clone actions found in policy '{policy_name}'. No settings to apply or check."]

    any_actual_changes_needed_for_policy = False
    dry_run_messages = []

    # Removed duplicate PWA exclusion print here as it's now handled in load_config_from_file


    for action in actions_to_process:
        action_name = action.get('Action Name')
        workflow_name = action.get('Workflow Name')
        current_dd_ret_apply = action.get('DD Ret Apply?')
        current_dd_ret_lock_time = action.get('DD Ret Lock Time')
        
        needs_update = False
        if current_dd_ret_apply != 'Yes':
            needs_update = True
        if (current_dd_ret_lock_time or '').lower() != (desired_retention_time or '').lower():
            needs_update = True

        is_excluded = False
        for exclusion in config.pwa_exclusions:
            policy_match = exclusion['policy'].lower() == action.get('Policy Name', '').lower()
            workflow_match = exclusion['workflow'].lower() == action.get('Workflow Name', '').lower()
            
            if policy_match and workflow_match:
                if exclusion['action'] is None:
                    is_excluded = True
                    break
                elif exclusion['action'].lower() == action.get('Action Name', '').lower():
                    is_excluded = True
                    break

        if is_excluded:
            continue 

        if needs_update:
            any_actual_changes_needed_for_policy = True
            msg = f"  [Dry Run] Action '{action_name}' in workflow '{workflow_name}':"
            if current_dd_ret_apply != 'Yes':
                msg += f"\n    - DD Ret Apply? would change from '{current_dd_ret_apply}' to 'Yes'"
            if (current_dd_ret_lock_time or '').lower() != (desired_retention_time or '').lower():
                msg += f"\n    - DD Ret Lock Time would change from '{current_dd_ret_lock_time}' to '{desired_retention_time}'"
            dry_run_messages.append(msg)
        else:
            dry_run_messages.append(f"  [Dry Run] Action '{action_name}' in workflow '{workflow_name}' is already configured correctly. No changes.")

    return any_actual_changes_needed_for_policy, dry_run_messages

def perform_policy_updates(server: str, policy_name: str, policy_type: str, config: NetWorkerConfig) -> None:
    """
    Applies DD retention lock settings to actions within a specified policy based on type.
    This function performs the actual updates.
    """
    desired_retention_time = config.retention_lock_times.get(policy_type.upper())
    if not desired_retention_time:
        print(f"Error: Invalid policy type '{policy_type}' for update operation.", file=sys.stderr)
        return

    policy_name_cleaned_lower = policy_name.strip().lower()
    all_policy_actions = get_all_policy_action_details(server)
    
    actions_to_process = [
        action for action in all_policy_actions
        if action.get('Policy Name', '').lower() == policy_name_cleaned_lower and action.get('Action Name') != 'Clone'
    ]

    if not actions_to_process:
        print(f"No non-Clone actions found in policy '{policy_name}'. No updates to apply.")
        return

    print(f"\nApplying updates for policy '{policy_name}' for type '{policy_type}'...")

    for action in actions_to_process:
        action_name = action.get('Action Name')
        workflow_name = action.get('Workflow Name')
        current_dd_ret_apply = action.get('DD Ret Apply?')
        current_dd_ret_lock_time = action.get('DD Ret Lock Time')
        
        needs_update = False
        if current_dd_ret_apply != 'Yes':
            needs_update = True
        if (current_dd_ret_lock_time or '').lower() != (desired_retention_time or '').lower():
            needs_update = True

        is_excluded = False
        for exclusion in config.pwa_exclusions:
            if exclusion['policy'].lower() == action.get('Policy Name', '').lower() and \
               exclusion['workflow'].lower() == action.get('Workflow Name', '').lower():
                if exclusion['action'] is None:
                    is_excluded = True
                    break
                elif exclusion['action'].lower() == action.get('Action Name', '').lower():
                    is_excluded = True
                    break

        if is_excluded:
            exclusion_reason = f"Policy '{action.get('Policy Name')}', Workflow '{action.get('Workflow Name')}'"
            if exclusion['action']:
                exclusion_reason += f", Action '{action.get('Action Name')}'"
            print(f"Skipping update for {exclusion_reason} as it is in the PWA Exclusion list.")
            if logger:
                logger.info(f"Skipping update for {exclusion_reason} due to PWA Exclusion list.")
            continue

        if needs_update:
            print(f"  Updating action '{action_name}' in workflow '{workflow_name}':")
            print(f"    - Current DD Ret Apply?: '{current_dd_ret_apply}', Current DD Ret Lock Time: '{current_dd_ret_lock_time}'")
            print(f"    - Desired DD Ret Apply?: 'Yes', Desired DD Ret Lock Time: '{desired_retention_time}'")
            
            update_cmd = (f". type: NSR protection policy action; policy name: \\\"{action.get('Policy Name')}\\\"; "
                          f"workflow name: \\\"{workflow_name}\\\"; name: \\\"{action_name}\\\"\n"
                          f"update Apply DD retention lock: Yes; DD retention lock time: \\\"{desired_retention_time}\\\"\\n"
                          f"y\\nquit")
            
            update_output = run_nsradmin_command(update_cmd, server, is_update_command=True)

            # Check for the specific failure prefix or "Update successful"
            if update_output.startswith("UPDATE_FAILED_INTERNAL_ERROR:"):
                error_details = update_output[len("UPDATE_FAILED_INTERNAL_ERROR:"):]
                print(f"    Failed to update action '{action_name}'. Details: {error_details}", file=sys.stderr)
            elif "Update successful" in update_output:
                print(f"    Successfully updated action '{action_name}'.")
            else:
                print(f"    NetWorker update command returned unexpected output or failed. Output:\n{update_output}", file=sys.stderr)
        else:
            print(f"  Action '{action_name}' in workflow '{workflow_name}' is already configured correctly. No changes applied.")

    print(f"\nFinished applying updates for policy '{policy_name}' for type '{policy_type}'.")


def print_device_table(mapping: List[Dict[str, str]], title: str = "Device Information:"):
    """Prints the Data Domain and Device information in a table."""
    if not mapping:
        print(f"\nNo {title.lower().replace(':', '')} found.")
        return

    headers = [
        "DD Name", "Device name", "mgmt host", "mgmt user", "mgmt passwd",
        "mgmt port", "SNMP Comm.", "DD Ret lock mode", "DD Ret min", "DD Ret Max"
    ]

    col_widths = {header: len(header) for header in headers}
    for entry in mapping:
        for header in headers:
            col_widths[header] = max(col_widths[header], len(entry.get(header, 'N/A') or 'N/A'))

    for header in headers:
        col_widths[header] = max(col_widths[header], 12)

    print(f"\n{title}")
    header_row = " | ".join(h.ljust(col_widths[h]) for h in headers)
    print(header_row)
    print("-" * len(header_row))
    for entry in mapping:
        row = [(entry.get(col, 'N/A') or 'N/A').ljust(col_widths[col]) for col in headers]
        # Mask password in display table
        if "mgmt passwd" in entry and entry["mgmt passwd"] != "N/A":
            row[headers.index("mgmt passwd")] = "*******".ljust(col_widths["mgmt passwd"])
        print(" | ".join(row))


def print_policy_table(policies_actions_info: List[Dict[str, str]], title: str = "Policy Information:"):
    """Prints the policy, workflow, and action information in a table."""
    if not policies_actions_info:
        print(f"\nNo {title.lower().replace(':', '')} found.")
        return

    headers = [
        'Policy Name', 'Workflow Name', 'Action Name',
        'Dest Storage Node', 'Dest Pool', 'Retention',
        'DD Ret Apply?', 'DD Ret Lock Time'
    ]

    col_widths = {header: len(header) for header in headers}
    for action in policies_actions_info:
        for header in headers:
            col_widths[header] = max(col_widths[header], len(action.get(header, 'N/A') or 'N/A'))

    for header in headers:
        col_widths[header] = max(col_widths[header], 12)

    print(f"\n{title}")
    header_row = " | ".join(h.ljust(col_widths[h]) for h in headers)
    print(header_row)
    print("-" * len(header_row))

    for action_data in policies_actions_info:
        row = [
            action_data.get('Policy Name', 'N/A'),
            action_data.get('Workflow Name', 'N/A'),
            action_data.get('Action Name', 'N/A'),
            action_data.get('Dest Storage Node', 'N/A'),
            action_data.get('Dest Pool', 'N/A'),
            action_data.get('Retention', 'N/A'),
            action_data.get('DD Ret Apply?', 'N/A'),
            action_data.get('DD Ret Lock Time', 'N/A')
        ]
        print(" | ".join(str(val or 'N/A').ljust(col_widths[headers[i]]) for i, val in enumerate(row)))

def parse_retention_lock_times_string(retention_str: str) -> Dict[str, str]:
    """Parses a string like 'FS = "14 days", PDB = "14 days"' into a dictionary."""
    parsed_times = {}
    
    # Remove outer braces if present
    retention_str = retention_str.strip()
    if retention_str.startswith('{') and retention_str.endswith('}'):
        retention_str = retention_str[1:-1]
    
    pairs = retention_str.split(',')
    for pair in pairs:
        match = re.match(r'^\s*(\w+)\s*=\s*"(.*?)"\s*$', pair.strip())
        if match:
            key = match.group(1).strip().upper() # Ensure keys are uppercase
            value = match.group(2).strip()
            parsed_times[key] = value
    return parsed_times

def _parse_custom_list_section(file_path: str, start_comment: str) -> List[str]:
    """
    Generic function to parse a custom list section from the config file.
    Reads lines after 'start_comment' until an empty line or new section.
    Ignores lines starting with '#'.
    """
    parsed_list = []
    in_list_section = False
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line_stripped = line.strip()
                
                if line_stripped.startswith(start_comment):
                    in_list_section = True
                    continue # Skip the comment line itself
                
                if in_list_section:
                    if not line_stripped or line_stripped.startswith('['): # End of list section
                        break
                    
                    if line_stripped.startswith('#'): # Ignore comments within the list
                        continue
                    
                    # Remove inline comments and strip whitespace
                    if '#' in line_stripped:
                        line_stripped = line_stripped.split('#', 1)[0].strip()
                    
                    if line_stripped: # Add only if there's content after stripping
                        parsed_list.append(line_stripped)
    except FileNotFoundError:
        logger.warning(f"Config file '{file_path}' not found during custom list parsing for '{start_comment}'. Returning empty list.")
    except Exception as e:
        logger.warning(f"Error parsing custom list for '{start_comment}' from '{file_path}': {e}. Returning partially parsed list.")
    return parsed_list


def load_config_from_file(config_file_path: str) -> NetWorkerConfig:
    """Loads configuration from the specified file and returns a NetWorkerConfig object."""
    config = NetWorkerConfig()
    
    if not config_file_path or not os.path.exists(config_file_path):
        # If no config file path is given or it doesn't exist, return empty config
        # This prevents the NoneType error for display mode when no config is provided
        logger.info(f"No config file specified or found at '{config_file_path}'. Returning empty configuration.")
        return config

    try:
        # Read the entire file content to separate INI sections from custom lists
        file_content_raw = []
        with open(config_file_path, 'r') as f:
            file_content_raw = f.readlines()

        ini_section_lines = []
        # Find the start of custom list sections to exclude them from configparser
        dd_list_start_index = -1
        nsr_dev_list_start_index = -1

        for i, line in enumerate(file_content_raw):
            if line.strip().startswith('# List of Data Domain Systems to be updated.'):
                dd_list_start_index = i
            if line.strip().startswith('# list of NSR Devices to be updated with "DD retention Lock mode"'):
                nsr_dev_list_start_index = i
            
            # Add lines to ini_section_lines only if they are before any custom list sections
            if (dd_list_start_index == -1 or i < dd_list_start_index) and \
               (nsr_dev_list_start_index == -1 or i < nsr_dev_list_start_index):
                ini_section_lines.append(line)

        config_parser_content = "".join(ini_section_lines)

        config_parser_obj = configparser.ConfigParser()
        config_parser_obj.read_string(config_parser_content)

        # Load Data Domain Configuration
        if 'Data Domain Configuration' in config_parser_obj:
            dd_config = config_parser_obj['Data Domain Configuration']
            config.data_domain_system = dd_config.get('DATA_DOMAIN_SYSTEM')
            config.snmp_community_string = dd_config.get('SNMP_COMMUNITY_STRING')
            config.management_host = dd_config.get('MANAGEMENT_HOST')
            config.management_user = dd_config.get('MANAGEMENT_USER')
            config.management_password = dd_config.get('MANAGEMENT_PASSWORD')
        
        # Load NSR Device Configuration
        if 'NSR Device Configuration' in config_parser_obj:
            dev_config = config_parser_obj['NSR Device Configuration']
            config.data_domain_name = dev_config.get('DATA_DOMAIN_NAME')
            config.nsr_device_name = dev_config.get('NSR_DEVICE_NAME')
            config.dd_retention_lock_mode = dev_config.get('DD_RETENTION_LOCK_MODE')

        # Load Policy Configuration (no longer directly loads retention_lock_times here)
        if 'Policy Configuration' in config_parser_obj:
            pol_config = config_parser_obj['Policy Configuration']
            apply_dd_ret_lock = pol_config.get('APPLY_DD_RETENTION_LOCK', 'no').lower()
            config.apply_dd_retention_lock = apply_dd_ret_lock in ['yes', 'true', '1']
            
        # Load Retention Lock Period
        if 'Retention Lock Period' in config_parser_obj:
            retention_lock_period = config_parser_obj['Retention Lock Period']
            retention_keys = ['FS', 'PDB', 'NPDB', 'NFS', 'DDBOOST']
            for key in retention_keys:
                if key in retention_lock_period:
                    config.retention_lock_times[key.upper()] = retention_lock_period.get(key)


        # Load custom Data Domain wildcard list
        config.data_domain_wildcard_list = _parse_custom_list_section(
            config_file_path, '# List of Data Domain Systems to be updated.'
        )
        # Load custom NSR Device wildcard list
        config.nsr_device_wildcard_list = _parse_custom_list_section(
            config_file_path, '# list of NSR Devices to be updated with "DD retention Lock mode"'
        )

        # Load PWA Exclusion list
        config.pwa_exclusions = []
        # Corrected start_comment to match the config file exactly
        pwa_exclusion_lines = _parse_custom_list_section(
            config_file_path, '# Policy |Workflow | Action'
        )
        for line in pwa_exclusion_lines:
            try:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2:
                    policy = parts[0]
                    workflow = parts[1]
                    # Fix: Correctly interpret empty string or "None" or "ALL" for action as Python None
                    action_val = parts[2].strip() if len(parts) > 2 else ''
                    action = None if action_val.lower() in ['none', 'all'] or not action_val else action_val
                    config.pwa_exclusions.append({'policy': policy, 'workflow': workflow, 'action': action})
                else:
                    if logger:
                        logger.warning(f"Invalid format in PWA Exclusion list: '{line}'. Skipping.")
            except IndexError:
                if logger:
                    logger.warning(f"Invalid line format in PWA Exclusion list: '{line}'. Skipping.")


        # Enhanced validation for new fields
        required_configs = {}
        
        if config.data_domain_system and config.data_domain_system.strip():
            required_configs.update({
                'SNMP_COMMUNITY_STRING': config.snmp_community_string,
                'MANAGEMENT_HOST': config.management_host,
                'MANAGEMENT_USER': config.management_user,
                'MANAGEMENT_PASSWORD': config.management_password,
            })
        
        if config.nsr_device_name and config.nsr_device_name.strip():
            required_configs.update({
                'DD_RETENTION_LOCK_MODE': config.dd_retention_lock_mode
            })
        
        missing_configs = [key for key, value in required_configs.items() if not value]
        if missing_configs:
            print(f"Error: Missing required configuration values for specified operations: {', '.join(missing_configs)}", file=sys.stderr)
            sys.exit(1)
        
        if not config.retention_lock_times:
            print("Error: No retention lock times found in configuration. Please specify FS, PDB, NPDB, NFS, and/or DDBOOST values.", file=sys.stderr)
            sys.exit(1)

        print(f"Configuration loaded successfully from '{config_file_path}'.")
        
        # Show configuration summary
        if config.data_domain_system:
            print(f"Data Domain Systems to update: {config.data_domain_system}")
        if config.nsr_device_name:
            print(f"NSR Devices to update: {config.nsr_device_name}")
            if config.data_domain_name:
                print(f"Filtered by Data Domain: {config.data_domain_name}")
        print(f"Loaded retention lock times: {config.retention_lock_times}")
        if config.data_domain_wildcard_list:
            print(f"Data Domain wildcard list from config: {', '.join(config.data_domain_wildcard_list)}")
        if config.nsr_device_wildcard_list:
            print(f"NSR Device wildcard list from config: {', '.join(config.nsr_device_wildcard_list)}")
        
        # Updated PWA exclusion list output
        if config.pwa_exclusions:
            print("Following workflows-> actions won't be updated:")
            for exclusion in config.pwa_exclusions:
                action_display = "ALL" if exclusion['action'] is None else exclusion['action']
                print(f"  {exclusion['policy']}|{exclusion['workflow']}|{action_display}")
        else:
            print("No PWA Exclusions configured.")
        
        return config
        
    except configparser.Error as e:
        print(f"Error parsing configuration file '{config_file_path}': {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{config_file_path}'.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while loading config: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    # Setup logging as the very first thing in main
    setup_logging()

    parser = argparse.ArgumentParser(description='NetWorker Device and Policy Information Script')
    
    parser.add_argument('-s', '--server', required=True, help='NetWorker server hostname')

    # Configuration File Option - now conditional based on operation type
    parser.add_argument('-f', '--config-file', type=str, 
                       help='Path to the external configuration file (Required for update operations, ignored for display operations)')

    # Display Options (mutually exclusive with each other for simplicity in display, but not with update flags)
    display_group = parser.add_mutually_exclusive_group()
    display_group.add_argument('--show-all', action='store_true', help='Display all Data Domain, Device, and Policy information.')
    display_group.add_argument('--show-dd', type=str, metavar='DATA_DOMAIN_NAME or ALL', help='Display details of the specified Data Domain. With "ALL" option display ALL DATA Domain Systems and all NSR Devices from the list specified either in command or in config file on specified networker server.')
    display_group.add_argument('--show-dev', type=str, metavar='NSR_DEVICE_NAME or ALL', help='Display details of the specified NSR Device. With "ALL" option display ALL NSR Devices from the list specified either in command or in config file on specified networker server.')
    display_group.add_argument('--show-pol', type=str, metavar='POLICY_NAME or ALL', help='Display the specified policy, including its workflows and actions (excluding "Clone" actions). if ALL display ALL policies, workflows and actions on specified networker server.')

    # Enhanced Action (Update) Options with wildcard support
    parser.add_argument('-dd', '--data-domain-update', type=str, metavar='DD_SYSTEM_NAME', 
                       help='Update Data Domain management configurations. Use "*" or "ALL" for all DDs, specific name, or comma-separated list.')
    parser.add_argument('-dev', '--device-update', type=str, metavar='NSR_DEVICE_NAME',
                       help='Update NetWorker Device retention settings. Use "*" or "ALL" for all devices (only valid with specific DD), specific name, or comma-separated list.')
    parser.add_argument('-pol', '--policy-update', type=str, help='Specify a policy name to enable DD retention lock on its actions.')
    parser.add_argument('-type', '--policy-type', type=str, 
                        help='Mandatory with -pol when used for updates. Specifies the type for DD retention lock time (fs, pdb, npdb, nfs, ddboost).')

    args = parser.parse_args()

    # Determine if this is a display operation or update operation
    is_display_operation = args.show_all or args.show_dd or args.show_dev or args.show_pol
    is_update_operation = args.data_domain_update or args.device_update or args.policy_update

    # Configuration file handling: Load config only if needed, or if specified
    config = NetWorkerConfig() # Initialize with an empty config first
    if is_update_operation and not args.config_file:
        parser.error("Configuration file (-f/--config-file) is required for update operations.")
    
    if args.config_file: # Attempt to load config if a file path is provided
        try:
            config = load_config_from_file(args.config_file)
        except SystemExit: # Catch the sys.exit(1) from load_config_from_file
            sys.exit(1) # Re-exit if config loading failed critically

    # If no config file was provided for display mode, config remains empty NetWorkerConfig()
    # This addresses the "NoneType" error when config_file is None.

    # Enhanced validation for new wildcard combinations
    if args.data_domain_update and args.device_update:
        dd_is_wildcard = args.data_domain_update.strip().upper() in ["*", "ALL"]
        dev_is_wildcard = args.device_update.strip().upper() in ["*", "ALL"]
        
        # The only truly invalid combination is if -dev is specific but -dd is not a wildcard or list.
        # This is implicitly handled by should_apply_device_config_from_cmdline if it returns False.
        # The previous explicit error check for -dd * and -dev * is removed, as it's now valid.
        pass # No explicit error for these new valid combinations at this stage

    # Validate -pol and -type combination for update
    if is_update_operation and args.policy_update and not args.policy_type:
        parser.error("--type is required when --pol is used for updates.")
    if is_update_operation and args.policy_type and not args.policy_update:
        parser.error("--pol is required when --type is used.")
    
    # Validation for policy-type against loaded configuration (only if update is intended)
    if is_update_operation and args.policy_type and args.policy_type.upper() not in config.retention_lock_times:
        parser.error(f"Invalid policy type '{args.policy_type}'. Valid types are: {', '.join(k.lower() for k in config.retention_lock_times.keys())}")
    
    if not is_display_operation and not is_update_operation:
        print("Error: No operation specified. Use --help for usage information.")
        sys.exit(1)

    print("NetWorker Device and Policy Information Report")
    print("=" * 60)
    print(f"Server: {args.server}")
    if args.config_file:
        print(f"Configuration loaded from: {args.config_file}")
    
    # Show command-line targets if specified
    if args.data_domain_update:
        print(f"Data Domain target (command-line): {args.data_domain_update}")
    if args.device_update:
        print(f"Device target (command-line): {args.device_update}")
    
    print()

    # Always retrieve all data, as it might be needed for display or updates
    print("Retrieving device and Data Domain information...")
    dd_cmd = ". type:NSR Data Domain\np"
    device_cmd = ". type:NSR device; media type: Data Domain\np"

    # Pass is_display_operation to run_nsradmin_command
    dds = parse_nsradmin_blocks(run_nsradmin_command(dd_cmd, args.server, is_display_mode=is_display_operation))
    devices = parse_nsradmin_blocks(run_nsradmin_command(device_cmd, args.server, is_display_mode=is_display_operation))
    all_dd_device_mapping = build_dd_device_mapping(dds, devices)

    print("Retrieving policy, workflow, and action information...")
    # Pass is_display_operation to get_all_policy_action_details
    all_policies_actions_info = get_all_policy_action_details(args.server, is_display_mode=is_display_operation)

    # --- Display Mode ---
    if is_display_operation:
        print("\n" + "=" * 60)
        print("Script run in Display Mode.")
        print("=" * 60)

        if args.show_all:
            print_device_table(all_dd_device_mapping)
            print_policy_table(all_policies_actions_info)
        
        if args.show_dd:
            # Handle 'ALL' or '*' for --show-dd
            if args.show_dd.strip().upper() in ["*", "ALL"]:
                # If config has a DD wildcard list, use it to filter
                if config.data_domain_wildcard_list:
                    filtered_dds = [d for d in all_dd_device_mapping if d.get('DD Name', '') in config.data_domain_wildcard_list]
                    print_device_table(filtered_dds, title=f"All Data Domain Systems from config list:")
                else:
                    # Otherwise, show all discovered DDs
                    print_device_table(all_dd_device_mapping, title=f"All Discovered Data Domain Systems:")
            else:
                filtered_dds = [d for d in all_dd_device_mapping if should_apply_dd_config_from_cmdline(d.get('DD Name', ''), args.show_dd, config)]
                print_device_table(filtered_dds, title=f"Data Domain Information for '{args.show_dd}':")
        
        if args.show_dev:
            # Handle 'ALL' or '*' for --show-dev
            if args.show_dev.strip().upper() in ["*", "ALL"]:
                # If config has an NSR device wildcard list, use it to filter
                if config.nsr_device_wildcard_list:
                    filtered_devs = [d for d in all_dd_device_mapping if d.get('Device name', '') in config.nsr_device_wildcard_list]
                    print_device_table(filtered_devs, title=f"All NSR Devices from config list:")
                else:
                    # Otherwise, show all discovered devices
                    print_device_table(all_dd_device_mapping, title=f"All Discovered NSR Devices:")
            else:
                filtered_devs = [d for d in all_dd_device_mapping if should_apply_device_config_from_cmdline(d.get('Device name', ''), d.get('DD Name', ''), args.show_dev, args.show_dd if args.show_dd else "", config)]
                print_device_table(filtered_devs, title=f"Device Information for '{args.show_dev}':")

        if args.show_pol:
            # Handle 'ALL' or '*' for --show-pol
            if args.show_pol.strip().upper() in ["*", "ALL"]:
                print_policy_table(all_policies_actions_info, title=f"All Policies, Workflows, and Actions:")
            else:
                filtered_policies = [p for p in all_policies_actions_info if p.get('Policy Name', '').lower() == args.show_pol.lower()]
                print_policy_table(filtered_policies, title=f"Policy Information for '{args.show_pol}':")

        print("\n" + "=" * 60)
        print("Display mode finished. Exiting.")
        print("=" * 60)
        sys.exit(0) # Exit after display

    # --- Action (Update) Mode ---
    # Only proceed to update if no display options were used
    if is_update_operation:
        print("\n" + "=" * 60)
        print("Script run in Update Mode.")
        print("=" * 60)

        # --- Data Domain Configuration Pre-Check and Update Section ---
        if args.data_domain_update:
            print("\n" + "=" * 60)
            print("Checking Data Domain management configurations for discrepancies...")

            current_dds_for_check = parse_nsradmin_blocks(run_nsradmin_command(dd_cmd, args.server)) # Not in display mode, so logs
            current_dd_map_for_check = {dd.get('name', ''): dd for dd in current_dds_for_check if dd.get('name')}

            # Filter Data Domains based on command-line argument using the new logic
            unique_dd_names_to_process = set()
            for dd_info in all_dd_device_mapping:
                dd_name = dd_info.get('DD Name')
                if dd_name and dd_name != "N/A" and should_apply_dd_config_from_cmdline(dd_name, args.data_domain_update, config):
                    unique_dd_names_to_process.add(dd_name)

            if not unique_dd_names_to_process:
                print(f"No Data Domains found matching command-line criteria: {args.data_domain_update}")
                print("=" * 60)
            else:
                print(f"Data Domains to be processed: {', '.join(sorted(unique_dd_names_to_process))}")

                all_dd_discrepancies: Dict[str, Dict[str, Tuple[str, str]]] = {}

                for dd_name in unique_dd_names_to_process:
                    actual_current_dd_config = current_dd_map_for_check.get(dd_name)
                    if actual_current_dd_config:
                        discrepancies = check_and_apply_datadomain_config(
                            args.server,
                            dd_name,
                            actual_current_dd_config,
                            config,
                            dry_run=True
                        )
                        if discrepancies:
                            all_dd_discrepancies[dd_name] = discrepancies
                    else:
                        print(f"Warning: Could not find current configuration for Data Domain '{dd_name}'. Cannot check for discrepancies.", file=sys.stderr)

                if not all_dd_discrepancies:
                    print("\nAll specified Data Domain management configurations are already in the desired state.")
                else:
                    print("\nData Domain Management Discrepancies found:")
                    for dd_name, discrep_details in all_dd_discrepancies.items():
                        print(f"  Data Domain: {dd_name}")
                        for key, (current_val, desired_val) in discrep_details.items():
                            if key == 'management password':
                                print(f"    - {key}: {current_val} -> ******** (new password will be set)")
                            else:
                                print(f"    - {key}: '{current_val}' -> '{desired_val}'")
                    
                    update_dd_mgmt = input("\nDo you want to apply these Data Domain management configuration updates? (yes/no): ").lower()

                    if update_dd_mgmt == 'yes':
                        print("\nStarting Data Domain management configuration updates...")
                        current_dds_for_apply = parse_nsradmin_blocks(run_nsradmin_command(dd_cmd, args.server)) # Not in display mode, so logs
                        current_dd_map_for_apply = {dd.get('name', ''): dd for dd in current_dds_for_apply if dd.get('name')}

                        for dd_name in all_dd_discrepancies.keys():
                            actual_current_dd_config = current_dd_map_for_apply.get(dd_name)
                            if actual_current_dd_config:
                                check_and_apply_datadomain_config(
                                    args.server,
                                    dd_name,
                                    actual_current_dd_config,
                                    config,
                                    dry_run=False
                                )
                            else:
                                print(f"Error: Data Domain '{dd_name}' disappeared or became unreadable during update phase. Skipping.", file=sys.stderr)
                    else:
                        print("Skipping Data Domain management configuration updates.")
                print("=" * 60)

        # --- NetWorker Device DD Retention Lock Mode Pre-Check and Update Section ---
        if args.device_update:
            print("\n" + "=" * 60)
            print("Checking NetWorker Device DD Retention Lock Mode configurations for discrepancies...")

            current_devices_for_check = parse_nsradmin_blocks(run_nsradmin_command(device_cmd, args.server)) # Not in display mode, so logs
            current_device_map_for_check = {dev.get('name', ''): dev for dev in current_devices_for_check if dev.get('name')}

            all_device_rlm_discrepancies: Dict[str, Dict[str, Tuple[str, str]]] = {}

            # Filter devices based on command-line arguments using the new logic
            devices_to_process = []
            for dev_info in all_dd_device_mapping:
                device_name = dev_info.get('Device name')
                dd_name = dev_info.get('DD Name')
                
                # Only consider devices that match the command-line criteria
                if (device_name and device_name != "N/A" and 
                    dd_name and dd_name != "N/A" and
                    should_apply_device_config_from_cmdline(device_name, dd_name, args.device_update, args.data_domain_update if args.data_domain_update else "", config) and
                    dev_info.get('DD Ret lock mode') != config.dd_retention_lock_mode):
                    
                    devices_to_process.append((device_name, dd_name))

            if not devices_to_process:
                print(f"No devices found matching command-line criteria.")
                print(f"Device target: {args.device_update}")
                if args.data_domain_update:
                    print(f"Data Domain filter: {args.data_domain_update}")
                print("=" * 60)
            else:
                print(f"Devices to be processed: {', '.join([f'{dev} (DD: {dd})' for dev, dd in devices_to_process])}")

                for device_name, dd_name in devices_to_process:
                    actual_current_device_config = current_device_map_for_check.get(device_name)
                    if actual_current_device_config:
                        discrepancies = check_and_apply_device_retention_lock_mode(
                            args.server,
                            device_name,
                            actual_current_device_config,
                            config,
                            dry_run=True
                        )
                        if discrepancies:
                            all_device_rlm_discrepancies[device_name] = discrepancies
                    else:
                        print(f"Warning: Could not find current configuration for device '{device_name}'. Cannot check for discrepancies.", file=sys.stderr)

                if not all_device_rlm_discrepancies:
                    print("\nAll specified NetWorker Device DD Retention Lock Modes are already in the desired state.")
                else:
                    print("\nNetWorker Device DD Retention Lock Mode Discrepancies found:")
                    for device_name, discrep_details in all_device_rlm_discrepancies.items():
                        print(f"  Device: {device_name}")
                        for key, (current_val, desired_val) in discrep_details.items():
                            print(f"    - {key}: '{current_val}' -> '{desired_val}'")
                    
                    update_device_rlm = input("\nDo you want to apply these NetWorker Device DD Retention Lock Mode updates? (yes/no): ").lower()

                    if update_device_rlm == 'yes':
                        print("\nStarting NetWorker Device DD Retention Lock Mode updates...")
                        current_devices_for_apply = parse_nsradmin_blocks(run_nsradmin_command(device_cmd, args.server)) # Not in display mode, so logs
                        current_device_map_for_apply = {dev.get('name', ''): dev for dev in current_devices_for_apply if dev.get('name')}

                        for device_name in all_device_rlm_discrepancies.keys():
                            actual_current_device_config = current_device_map_for_apply.get(device_name)
                            if actual_current_device_config:
                                check_and_apply_device_retention_lock_mode(
                                    args.server,
                                    device_name,
                                    actual_current_device_config,
                                    config,
                                    dry_run=False
                                )
                            else:
                                print(f"Error: Device '{device_name}' disappeared or became unreadable during update phase. Skipping.", file=sys.stderr)
                    else:
                        print("Skipping NetWorker Device DD Retention Lock Mode updates.")
                print("=" * 60)

        # --- Policy Configuration Section ---
        if args.policy_update and args.policy_type:
            print("\n" + "=" * 60)
            print(f"Checking policy '{args.policy_update}' for DD retention lock configuration with type '{args.policy_type}'...")
            
            # Perform dry run to determine if any changes are needed and get messages
            any_changes_needed, dry_run_messages = apply_policy_dd_retention_settings_dry_run(
                args.server, args.policy_update, args.policy_type, config
            )

            if any_changes_needed:
                # Only print dry run messages if changes are actually needed
                for msg in dry_run_messages:
                    print(msg)
                
                confirm_policy_update = input(f"\nDo you want to apply these changes to policy '{args.policy_update}'? (yes/no): ").lower()
                if confirm_policy_update == 'yes':
                    # If confirmed, perform the actual updates
                    perform_policy_updates(args.server, args.policy_update, args.policy_type, config)
                else:
                    print(f"Skipping updates for policy '{args.policy_update}'.")
            else:
                # If no changes are needed, print a concise message and skip the prompt
                print(f"Policy '{args.policy_update}' is already in the desired state. No updates required.")

            print("=" * 60)
    else:
        print("\nNo display or update options selected. Use --help for usage information.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nScript interrupted by user.") # Use info as it's a user action
        print("\nScript interrupted by user.", file=sys.stderr) # Console output
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True) # exc_info=True logs traceback
        print(f"An unexpected error occurred: {e}", file=sys.stderr) # Console output
        sys.exit(1)

