rule nanocore_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Nanocore RAT based on common static string artifacts"
        malware_family = "Nanocore"
        mitre_attack = "T1059, T1105, T1027"
        score = 86
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/nanocore_yara_patterns.md"

    strings:
        $s1 = "Nanocore Client" ascii
        $s2 = "ClientPluginHost" ascii
        $s3 = "StartModule" ascii
        $s4 = "runonce" ascii
        $s5 = "NanoHost" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
