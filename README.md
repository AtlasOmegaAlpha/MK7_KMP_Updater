# MK7 KMP Updater

This tool converts KMP files from Mario Kart 7 to a newer or older version, and allows to stripe/empty out individual sections.
Current supported versions are: 0xBB8 (E3 2010 demo) and 0xC1C (final version)

## Usage

```
Usage:  MK7_KMP_Updater [file1, file2 ...] (arguments)

Possible arguments:
═════════════════════╤═══════════╤═══════════════════════════════════════════════════════════════════
Argument (alias)     │ Parameter │ Description
═════════════════════╪═══════════╪═══════════════════════════════════════════════════════════════════
-help (-h)           │           │ Displays this tool's usage and list of possible arguments
─────────────────────┼───────────┼───────────────────────────────────────────────────────────────────
-version (-v)        │ Version   │ Converts the KMP to the specified version. Currently supported
                     │           │ versions: 0xC1C, 0xBB8
─────────────────────┼───────────┼───────────────────────────────────────────────────────────────────
-excludesection (-e) │ Sections  │ Completely excludes the specified comma-separated sections from
                     │           │ the file
─────────────────────┼───────────┼───────────────────────────────────────────────────────────────────
-excludeentry (-ee)  │ Sections  │ Excludes any entries from the specified comma-separated sections
                     │           │ from the file, leaving these sections empty
─────────────────────┴───────────┴─────────────────────────────────────────────────────────────────── 
```

The tool also allows using wildcards (for example, '*.kmp' would convert all files from the current directory)
