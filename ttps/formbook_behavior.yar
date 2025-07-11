rule formbook_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects FormBook behavior via HTTP-based exfiltration and credential form targeting"
        malware_family = "FormBook"
        mitre_attack = "T1056.001, T1041, T1113"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/formbook_c2_patterns.md"

    strings:
        $s1 = "POST /ulur" ascii
        $s2 = "Content-Type: application/x-www-form-urlencoded" ascii
        $s3 = "Form1" ascii wide

    condition:
        all of ($*)
}
