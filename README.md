<h1 align="center">
    <br>
    🔩 N.U.T.
</h1>

<h4 align="center">Nessus Utility Toolkit</h4>

<p align="center">
    The purpose of this tool is to automate and simplify common and time-consuming tasks involving Nessus.
    <br>
    It is still a work in progress and will be extended as I come across new, annoying processes.
</p>

# Installation

```
pipx install git+https://github.com/karrni/nessus-utility-toolkit
```

To upgrade, simply run

```
pipx upgrade nut
```

# Usage

Nut accepts **any amount and combination of scans and folders**. Scans have to be their ID, folders can be their ID or name. Folders are then resolved and scans contained within them are merged with the others. The resulting list of scan IDs is then passed to the respective module.

## Example

```
nut <MODULE> -s <SCAN> <SCAN> ... -f <FOLDER> <FOLDER> ...
```

### Where do I find ...

- **Scan ID** - can be found in the URL when viewing the scan (`/scans/reports/<SCAN_ID>/hosts`)
- **Folder ID** - in the URL when viewing the folder (`/scans/folders/<FOLDER_ID>`)
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
