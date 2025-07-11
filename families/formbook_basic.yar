rule formbook_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects FormBook samples using static string markers in payload"
        malware_family = "FormBook"
        mitre_attack = "T1056.001, T1557.002, T1566.001"
        score = 82
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/formbook_c2_patterns.md"

    strings:
        $s1 = "ulur" ascii
        $s2 = "http" ascii
        $s3 = "Form" ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of ($*)
}
