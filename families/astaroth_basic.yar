rule astaroth_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Astaroth stealer payloads via command-line patterns, .NET abuse, and credential dumping routines"
        malware_family = "Astaroth"
        mitre_attack = "T1059.003, T1055, T1218.009, T1555"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/astaroth_yara_patterns.md"

    strings:
        $cmd1 = "regsvr32.exe" ascii
        $cmd2 = "wmic.exe" ascii
        $dll1 = "efswrt.dll" ascii
        $dll2 = "ntdskutl.dll" ascii
        $arg1 = "/s /n /u /i" ascii
        $b64enc = "QVNURVJQQVNTR0VORA==" ascii  // base64 of "ASTERPASSGEND"

    condition:
        uint16(0) == 0x5A4D and
        3 of ($cmd*, $dll*, $arg1, $b64enc)
}
