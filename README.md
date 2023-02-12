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

```
pipx install git+https://github.com/karrni/nessus-utility-toolkit
```

To upgrade, simply run

```
pipx upgrade nut
```

## Configuration

To use nut, set the Nessus URL and either user credentials or API tokens in the configuration file which is located under `~/.config/nut.conf`. Upon first run, the example config file will be copied to this location.

The Nessus URL must not contain a path, so for example `https://nessus.local:8834`.

The API tokens can be generated under `/#/settings/my-account/api-keys`, which is under User (top right) > My Account > API Keys.

# Usage

Nut accepts **any amount and combination of scans and folders**. Scans have to be their ID, folders can be their ID or name. Folders are then resolved and scans contained within them are merged with the others. The resulting list of scan IDs is then passed to the respective module.

## Example

```
nut <MODULE> -s <SCAN> <SCAN> ... -f <FOLDER> <FOLDER> ...
```

### Where do I find ...

- **Scan ID** - can be found in the URL when viewing the scan (`/#/scans/reports/<SCAN_ID>/hosts`)
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
nut create --list-policies
nut create -i <INFILE>
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

If we want to create multiple scans, it's likely that they will use the same policy or be create in the same folder (each key can have a default value, including targets and exclusions). To avoid unnecessary repetitions, it's possible to define default values that can be overwritten by the respective scans if necessary.

```yaml
defaults:
  folder: 2022-07 Customer
  policy: All Ports

scans:
  Headquarters:
    targets:
      - 10.0.0.0/24
      - 10.0.1.0/24
    exclusions:
      - 10.0.0.100

  Branch Office:
    targets:
      - 10.2.0.0/24
    exclusions:
      - 10.2.0.100
      - 10.2.0.102

  Production:
    policy: Custom Fragile Policy
    targets:
      - 10.1.2.0/24
```
