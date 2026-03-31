# Map EFI Program Settings to NVRAM Key Values
This tool allows the operator to map possible control values in NVRAM to a given setting managed by an EFI program.
There are two analysis modes:
- Mode 1 : Map EFI program settings to NVRAM Variable/Values
- Mode 2 : Map NVRAM variable to EFI program settings
  
The tool is vendor agnostic and works against most modern UEFI implementations.

# Usage
```usage: nvramap.py [-h] -mode MODE -efi FILE -nvram FILE [-terms TERMS] [-all] [-guid GUID] [-key NAME] [--modify] [--set INDEX VALUE] [--extra-efi FILE [FILE ...]] [--dump-ifr FILE] [--dump-var GUID] [--debug]

NVRAMap — UEFI NVRAM Mapper & Editor

  Parses HII form data from any UEFI EFI module and maps firmware
  settings to their NVRAM variable store locations. Supports reading
  and writing live values in raw NVRAM binary blobs.

  Mode 1: Map EFI Settings  →  NVRAM Variables  (search by keyword)
  Mode 2: Map NVRAM Variables  →  EFI Settings  (reverse, by GUID+key)

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -mode MODE            Operation mode: 1 = EFI→NVRAM | 2 = NVRAM→EFI
  -efi FILE             Path to EFI module containing HII form data
  -nvram FILE           Path to raw NVRAM binary blob

mode 1 options:
  -terms TERMS, -t TERMS
                        Comma-separated search terms e.g. VT-d,IOMMU,DMA
  -all                  Dump every setting in the EFI (no search filter)

mode 2 options:
  -guid GUID            VarStore GUID e.g. FB3B9ECE-4ABA-4933-B49D-B4D67D892351
  -key NAME             NVRAM variable name e.g. HpDmarOptions

options:
  --modify              Interactive edit mode — select and modify values after display
  --set INDEX VALUE     Non-interactive write: set setting [INDEX] to VALUE (0x.. or decimal)
  --extra-efi FILE [FILE ...]
                        Additional EFI files to scan for VarStore GUID definitions
  --dump-ifr FILE       Save full extracted IFR text to FILE
  --dump-var GUID       Debug: dump all raw NVRAM entries for a given GUID
  --debug               Verbose parsing output

EXAMPLE USAGE:

  Mode 1 — Map EFI settings to NVRAM variables (search by keyword):
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms VT-d,IOMMU
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms DMA --modify
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms DMA --set 2 0x1

  Mode 2 — Map NVRAM variables to EFI settings (reverse lookup by GUID + key):
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid FB3B9ECE-4ABA-4933-B49D-B4D67D892351 -key HpDmarOptions
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid <GUID> -key <KeyName> --modify
```

# Demo (mode 1 - EFI Settings to NVRAM analysis)


# Demo (mode 2 - NVRAM to EFI Settings analysis)


# Explanation
Originally, my methodology for mampping NVRAM data the functionality it controlled involved arduous and time consuming targetted diffing of firmware dumps that matched the desired configuration state for further research. As expected, this method is time consuming and not suitable for large scale fuzzing or discovery of UEFI functionality. Then security researcher Craig Blackie sent me an article he wrote where he used IFRExtractor to determine control variables for Pre-Boot DMA Protection in Dell firmware. His methodology involved extracting the Setup.efi program from the firmware dump and analyzing its HII structures to identify the NVRAM variable store associated with various UI actions (like choosing setting values). In his article, he manually performs the mapping operation through a combination of UEFITools and output from the extractor, arriving at precise offsets in the setup NVRAM variable that control the behaviour of pre-boot DMA countermeasures. I was curious if this technique could be automated and used to map the relationship between arbitrary EFI programs and NVRAM in a vendor agnostic scanner. NVRAMap is the result of this questioning. The present program will use extracted HII data from the specified EFI program to map the settings it manages to NVRAM GUIDs and Keys. It will then automatically parse the specified NVRAM dump and map the settings to their present values. This can occur forward, or in reverse, in situations where an operator has an NVRAM section they are interested in but do not know what the data controls. Finally, the program can be used to modify the discovered setting values, creating a patched NVRAM file in the same directory which can later be used for flashing a target computer's EEPROM via universal programmer.
