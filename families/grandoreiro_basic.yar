rule grandoreiro_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Grandoreiro banking trojan via static string patterns"
        malware_family = "Grandoreiro"
        mitre_attack = "T1059, T1105, T1204"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/grandoreiro_yara_patterns.md"

    strings:
        $s1 = "hacker2bank" ascii
        $s2 = "C:\\ProgramData\\%s\\%s.exe" ascii
        $s3 = "Shell_TrayWnd" ascii
        $s4 = "SetWindowsHookExA" ascii
        $s5 = "WinSta0\\Default" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
