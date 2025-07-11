rule emotet_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Emotet behavioral traits via PowerShell injection, HTTP POST beaconing, and mutex artifacts"
        malware_family = "Emotet"
        mitre_attack = "T1055.001, T1105, T1027, T1071.001"
        score = 95
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/emotet_yara_patterns.md"

    strings:
        $ps_inject = "powershell -nop -w hidden -enc" ascii
        $post = "POST /news.php?id=" ascii
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        $zip_ext = ".zip" ascii
        $doc_macro = "Document_Open" ascii
        $dll_load = "rundll32.exe" ascii
        $mutex = "Global\\EMOTET" ascii

    condition:
        5 of them
}
