rule grandoreiro_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Grandoreiro runtime behavior including screen overlay and persistence routines"
        malware_family = "Grandoreiro"
        mitre_attack = "T1059, T1105, T1204"
        score = 88
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/grandoreiro_yara_patterns.md"

    strings:
        $overlay = "Shell_TrayWnd" ascii
        $mutex = "WinSta0\\Default" ascii
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $dir = "C:\\ProgramData\\" ascii
        $network = "/api/v1/" ascii

    condition:
        4 of them
}
