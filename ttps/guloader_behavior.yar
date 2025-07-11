rule guloader_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects GULoader behavior chain (XXE decoded -> drops DLLs -> Temp/User folder)"
        malware_family = "GULoader"
        mitre_attack = "T1204.002, T1059.003, T1055.001"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/guloader_c2_patterns.md"

    strings:
        $drop1 = "Temp\\" ascii
        $drop2 = "Users\\" ascii
        $drop3 = "DLL" ascii
        $stealth = "Cannot access folder until the sample stops running" ascii
        $stealth2 = "Some variants create random folders in Users" ascii

    condition:
        4 of ($*)
}
