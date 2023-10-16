<h1 align="center">
    <br>
    Nessus Utility Toolkit
</h1>

<p align="center">
    The purpose of this tool is to automate and simplify common and time-consuming tasks involving Nessus.
    <br>
    It's still a work in progress and will be extended as I come across new, annoying processes.
</p>

# Installation

Using pip (or even better, [pipx](https://pypa.github.io/pipx/)):

```
pip install nessus-utility-toolkit
```

Alternatively, you can install it from source using Poetry:

```
git clone https://github.com/karrni/nessus-utility-toolkit
cd nessus-utility-toolkit
poetry install
poetry run nut
```

After that, the `nut` command should be available from your command line.

## Configuration

To use nut, set the Nessus URL and either **user credentials** or **API tokens** in the configuration file which is located under `~/.config/nut.conf`. Upon first run, the example config file will be copied to this location.

The Nessus URL must not contain a path, so for example `https://nessus.local:8834`.

The API tokens can be generated under `/#/settings/my-account/api-keys`, which is under User (top right) > My Account > API Keys.

# Usage

Nut accepts **any amount and combination of scans and folders**. Both can be either their ID or name. Folders are then resolved and scans contained within them are merged with the others. The resulting list of scan IDs is then passed to the respective module.

## Example

```
nut <MODULE> -s <SCAN> <SCAN> ... -f <FOLDER> <FOLDER> ...
```

### Where do I find ...

- **Scan ID** - can be found in the URL when viewing the scan (`/#/scans/reports/<SCAN_ID>/hosts`)
- **Scan Name** - the exact name as it appears when viewing the folder (e.g. `"All Subnets"`)
- **Folder ID** - in the URL when viewing the folder (`/#/scans/folders/<FOLDER_ID>`)
- **Folder Name** - the exact name as it appears in the sidebar (e.g. `"My Scans"` or `2022-04-Client`)

# Modules

## Export

This module exports all scans. The folder structure and the scan names are retained. Optionally, all scans can be merged into one. Also, the destination folder can be set using the `-o` flag.

```
nut export -s <SCAN> -f <FOLDER>
nut export -f <FOLDER> --merge
```

## URLs

This module extracts all web servers found by the "Service Detection" plugin and writes the resulting list to a file. The default filename (webservers.txt) can be overwritten using the `-o` flag.

```
nut urls -s <SCAN> -f <FOLDER>
```

## Create

This module allows to create scans automatically. It takes a JSON/YAML file that contains one or more scan definitions, which it processes and creates.

```
nut create <FILE>
```

### Definitions

Scan definitions consist of a name, a policy, and targets. Optionally, folder and description can be defined. It's also possible to define exclusions, which are automatically omitted when generating the target list.

For example, the target 10.0.0.0/24 with the exclusion 10.0.0.100 will yield 10.0.0.1-10.0.0.99, 10.0.0.101-10.0.0.254.

#### Single Scan

Let's say we want to create a scan named "Example Scan" that uses the "All Ports" scan policy in the "Example Folder" folder. The target of this scan is the entire 10.0.0.0/24 network, but we want to exclude 10.0.0.100 because it's a fragile printer.

```yaml
scans:
  Example Scan:
    description: The whole network without the printer
    folder: Example Folder
    policy: All Ports
    targets:
      - 10.0.0.0/24
    exclusions:
      - 10.0.0.100
```

#### Multiple Scans

If we want to create multiple scans, it's likely that they use the same policy or should be created in the same folder. To avoid unnecessary repetitions, it's possible to define default values for every key except `targets`:

```yaml
defaults:
  folder: 2022-07 Customer
  policy: All Ports
  exclusions:
    - 10.0.0.100

scans:
  Headquarters:
    targets:
      - 10.0.0.0/24
      - 10.0.1.0/24

  Branch Office:
    targets:
      - 10.2.0.0/24
      - 10.2.0.102
    exclusions:
      - 10.2.0.20

  Production:
    policy: Custom Fragile Policy
    targets:
      - 10.1.2.0/24
```

## Exploits

This module extracts all vulnerabilities that have known exploits. Optionally, we can filter them to only includes ones with a metasploit or core impact module.

```
nut exploits -s <SCAN> -f <FOLDER>
nut exploits -s <SCAN> -f <FOLDER> -ms
```
