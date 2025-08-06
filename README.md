# NetWorker Data Domain and Policy Management Tool

**Maintained by:** Dayanand Kadam (dayakadam@yahoo.com)

A command-line tool for managing NetWorker Data Domain devices and backup policies. This tool provides capabilities to view and update NetWorker configurations including Data Domain management settings, device retention locks, and policy configurations.

## Features

### v1.8.0 (Latest)

- **Enhanced PWA Exclusion List Output**: The script now immediately displays the PWA exclusion list in a user-friendly format (Policy|Workflow|Action or ALL) upon configuration loading.

- **Improved Error Reporting**: More precise error details for nsradmin update command failures, including authentication issues, by capturing both standard output and error streams.

- **Config File Retention Period**: Correctly reads retention lock times from the new [Retention Lock Period] section in the configuration file.

- **PWA Exclusion List Parsing Fixes**: Addressed multiple issues with parsing the PWA Exclusion list, ensuring correct interpretation of "ALL" and empty action fields as None, and consistent case-insensitive matching for policy, workflow, and action names.

- **Refactored Policy Update Logic**: Separated policy update into distinct dry-run and apply functions, with dry-run only displaying changes if updates are actually needed.

- **PWA Exclusion Support**: Added support for [PWA Exclusion list] section in the config file, allowing the script to skip policy/workflow/action updates if they are in the exclusion list.

### v1.7.0

- **Enhanced Wildcard Support**: Added support for [NSR Device list] section in the config file for more flexible wildcard filtering.

- **Improved Display Options**: --show-dd and --show-pol options now accept 'ALL' or '*' for displaying all relevant entities.

- **Display Mode Fix**: Resolved 'NoneType' error when running display commands without a config file.

### v1.6.0

- **Config File Parsing Fix**: Separated INI parsing from custom Data Domain list parsing, correctly reading custom list sections and ignoring comments (#).

### v1.5.0

- **Flexible Wildcard Logic**: Updated wildcard logic for -dd and -dev options to allow combinations like -dd * -dev *.

- **Config List Resolution**: Added support for parsing a list of Data Domain systems from the config file to resolve wildcards.

- **Comment Handling**: Comments (#) in the Data Domain list section of the config file are now properly ignored.

### v1.3.0

- **Logging Operations**: Added logging function to keep logs at /var/log/nwrkr-rlock/ folder.

### v1.2.0

- **Display Operations**: View Data Domain devices, NetWorker devices, and policy information

- **Update Operations**: Modify Data Domain management settings, device retention modes, and policy configurations

- **Wildcard Support**: Apply changes to all systems/devices or specific targets using * or ALL

- **Configuration Management**: External configuration file support for secure credential management

- **Dry-run Mode**: Preview changes before applying them

- **Comprehensive Reporting**: Tabular output with detailed device and policy information

## Requirements

- Python 3.6 or higher
- NetWorker client tools installed (nsradmin command available)
- Access to NetWorker server
- Appropriate NetWorker administrative privileges

## Installation

### Option 1: Direct Download

```bash
# Download the script
wget https://github.com/dayakadam/networker-rlock-tool/raw/main/networker_rlock_tool.py

# Make it executable
chmod +x nwrkr-rlock
```

### Option 2: Clone Repository

```bash
git clone https://github.com/dayakadam/networker-management-tool.git
cd networker-management-tool
chmod +x nwrkr-rlock
```

### Option 3: RPM Installation (RHEL/CentOS)

```bash
# Install the RPM package
sudo rpm -ivh nwrkr-rlock-1.8.0-1.el7_9.x86_64.rpm

# Use as system command
networker-tool --help
```

## Configuration

Create a configuration file for update operations:

```ini
# networker-config.ini
[Data Domain Configuration]
# Data Domain management settings
SNMP_COMMUNITY_STRING = your_snmp_community_string
MANAGEMENT_HOST = your_data_domain_host
MANAGEMENT_USER = your_mgmt_host_username
MANAGEMENT_PASSWORD = your_mgmt_host_password

[NSR Device Configuration]
# NetWorker device settings
NSR_DEVICE_NAME = your_nsr_device_name
DD_RETENTION_LOCK_MODE = dd_retention_lock_mode #Governance

[Policy Configuration]
# Policy-related settings
APPLY_DD_RETENTION_LOCK = yes_or_no #yes

[Retention Lock Period]
# Retention lock times for different policy types
# Each policy type is specified on a separate line
FS = 14 days
PDB = 14 days
NPDB = 7 days
NFS = 7 days
DDBOOST = 14 days

[Data Domain List]
# List of Data Domains for wildcard filtering (e.g., when -dd ALL is used)
# Each Data Domain name on a new line
# Comments start with #
bw01ddpe01x1-pn145
bw01ddpe02x1-pn146
# another_dd_system

[NSR Device list]
# List of NSR Devices for wildcard filtering (e.g., when -dev ALL is used)
# Each NSR Device name on a new line
# Comments start with #
bw01ddpe01x1-pn145_device1
bw01ddpe01x1-pn145_device2
# another_nsr_device

[PWA Exclusion list]
# Policy |Workflow | Action
# List of Policy, Workflow, Action combinations to exclude from updates.
# If Action is left blank or specified as "ALL", all actions within that Policy/Workflow will be excluded.
# Example:
# Bronze | Applications | Backup
# Silver | Applications | ALL
```

## Usage

### Display Operations (No config file required)

```bash
# Show all devices and policies
./nwrkr-rlock -s your_server --show-all

# Show specific Data Domain or all Data Domains
./nwrkr-rlock -s your_server --show-dd bw01ddpe01x1
./nwrkr-rlock -s your_server --show-dd ALL

# Show specific device or all devices
./nwrkr-rlock -s your_server --show-dev device_name
./nwrkr-rlock -s your_server --show-dev ALL

# Show specific policy or all policies
./nwrkr-rlock -s your_server --show-pol policy_name
./nwrkr-rlock -s your_server --show-pol ALL
```

### Update Operations (Config file required)

#### Data Domain Updates

```bash
# Update specific Data Domain
./nwrkr-rlock -s your_server -f config.ini -dd bw01ddpe01x1-pn145

# Update all Data Domains (use quotes!)
./nwrkr-rlock -s your_server -f config.ini -dd '*'

# Alternative: Use ALL to avoid quoting
./nwrkr-rlock -s your_server -f config.ini -dd ALL

# Update multiple specific Data Domains
./nwrkr-rlock -s your_server -f config.ini -dd "dd1,dd2,dd3"
```

#### Device Updates

```bash
# Update specific device
./nwrkr-rlock -s your_server -f config.ini -dev device_name

# Update all devices from specific Data Domain (use quotes!)
./nwrkr-rlock -s your_server -f config.ini -dd bw01ddpe01x1-pn145 -dev '*'

# Alternative: Use ALL to avoid quoting
./nwrkr-rlock -s your_server -f config.ini -dd bw01ddpe01x1-pn145 -dev ALL

# Update specific device from all Data Domains
./nwrkr-rlock -s your_server -f config.ini -dd ALL -dev specific_device

# Update all devices from all Data Domains (new valid combination)
./nwrkr-rlock -s your_server -f config.ini -dd ALL -dev ALL
```

#### Policy Updates

```bash
# Update policy for filesystem backups
./nwrkr-rlock -s your_server -f config.ini -pol "FS_Daily_Backup" -type fs

# Update policy for database backups
./nwrkr-rlock -s your_server -f config.ini -pol "DB_Backup_Policy" -type pdb
```

## Command Line Options

### Required Arguments

- `-s, --server`: NetWorker server hostname

### Display Options (Mutually exclusive)

- `--show-all`: Display all Data Domain, Device, and Policy information
- `--show-dd DATA_DOMAIN_NAME or ALL`: Display details of specified Data Domain, or all Data Domain Systems from the list specified in the config file (if ALL is used).
- `--show-dev NSR_DEVICE_NAME or ALL`: Display details of specified NSR Device, or all NSR Devices from the list specified in the config file (if ALL is used).
- `--show-pol POLICY_NAME or ALL`: Display specified policy details, or all policies, workflows, and actions on the NetWorker server (if ALL is used).

### Update Options

- `-f, --config-file`: Path to configuration file (required for updates)
- `-dd, --data-domain-update`: Update Data Domain management configurations. Accepts *, ALL, specific name, or comma-separated list.
- `-dev, --device-update`: Update NetWorker Device retention settings. Accepts *, ALL, specific name, or comma-separated list.
- `-pol, --policy-update`: Specify policy name for DD retention lock updates.
- `-type, --policy-type`: Policy type (fs, pdb, npdb, nfs, ddboost) - required with -pol

## Wildcard Support

### Valid Wildcards

- `*` or `ALL`: Apply to all discovered systems/devices (filtered by config list if present)
- `system1,system2,system3`: Comma-separated list for multiple specific targets
- `specific_name`: Single system/device name

### Wildcard Rules

- ✅ Valid: `-dd specific_dd -dev '*'` (all devices from specific DD)
- ✅ Valid: `-dd '*' -dev specific_device` (specific device from all DDs)
- ✅ Valid: `-dd '*' -dev '*'` (all devices from all DDs, filtered by config lists if specified)

### Shell Quoting

When using * on the command line, always use quotes to prevent shell expansion:

```bash
# Correct
./script.py -s server -f config.ini -dd bw01ddpe01x1 -dev '*'

# Alternative (no quotes needed)
./script.py -s server -f config.ini -dd bw01ddpe01x1 -dev ALL

# Wrong (shell will expand * to filenames)
./script.py -s server -f config.ini -dd bw01ddpe01x1 -dev *
```

## Examples

### Complete Workflow Examples

```bash
# 1. First, view current configuration
./nwrkr-rlock -s bw01nwsn06x1 --show-all

# 2. Update a specific Data Domain's SNMP settings
./nwrkr-rlock -s bw01nwsn06x1 -f config.ini -dd bw01ddpe01x1-pn145

# 3. Update all devices from that Data Domain
./nwrkr-rlock -s bw01nwsn06x1 -f config.ini -dd bw01ddpe01x1-pn145 -dev '*'

# 4. Update a filesystem backup policy
./nwrkr-rlock -s bw01nwsn06x1 -f config.ini -pol "FS_Daily" -type fs

# 5. Verify changes
./nwrkr-rlock -s bw01nwsn06x1 --show-dd bw01ddpe01x1-pn145
```

## Security Notes

- Store configuration files with restricted permissions: `chmod 600 config.ini`
- Keep configuration files outside of version control
- Use service accounts with minimal required privileges
- Consider using environment variables for sensitive data in production

## Troubleshooting

### Common Issues

**"nsradmin command not found"**
- Ensure NetWorker client tools are installed
- Add NetWorker binaries to PATH: `export PATH=/usr/bin:$PATH`

**"Configuration file required for update operations"**
- Provide config file with -f option for any update operation
- Config file not needed for display operations

**"unrecognized arguments" when using ***
- Use quotes around the asterisk: `-dev '*'`
- Or use ALL instead: `-dev ALL`

**"Permission denied"**
- Ensure your user has appropriate NetWorker administrative privileges
- Check NetWorker server authentication settings

## Output Format

The tool displays information in organized tables:

### Device Information Table

| DD Name | Device name | mgmt host | SNMP Comm. | DD Ret lock mode |
|---------|-------------|-----------|------------|------------------|
| Datadomain_system_name | device_name_123 | 10.1.1.100 | community123 | Governance |

### Policy Information Table

| Policy Name | Workflow Name | Action Name | DD Ret Apply? | DD Ret Lock Time |
|-------------|---------------|-------------|---------------|------------------|
| FS_Daily_Backup | workflow1 | Backup | Yes | 14 days |

## Version History

- **v1.8.0**: Added support for [PWA Exclusion list] section in the config file, enabling skipping of policy/workflow/action updates.
            : Updated config file parsing to correctly read retention lock times from the [Retention Lock Period] section. 
            : Fixed PWA Exclusion list parsing to correctly interpret empty action fields as None.
- **v1.7.0**: Added [NSR Device list] support, fixed display mode NoneType error, and enhanced --show-dd/--show-pol with 'ALL' option.
- **v1.6.0**: Fixed config file parsing error by separating INI parsing from custom Data Domain list parsing.
- **v1.5.0**: Updated wildcard logic for -dd/-dev to allow -dd * -dev *, added config file list parsing, and improved comment handling.
- **v1.3.0**: Added logfile support.
- **v1.2.0**: Added command-line wildcard support, enhanced validation.
- **v1.1.0**: Added configuration file wildcard support, selective updates.
- **v1.0.0**: Initial release with basic display and update functionality.

## Support

For issues, questions, or feature requests:

- Check the troubleshooting section above
- Review command syntax and examples
- Verify NetWorker client tools installation
- Contact: Dayanand Kadam (dayakadam@yahoo.com)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
