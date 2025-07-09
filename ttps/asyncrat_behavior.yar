rule asyncrat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Behavioral detection of AsyncRAT via registry persistence, PowerShell execution, and command usage"
        malware_family = "AsyncRAT"
        mitre_attack = "T1547.001, T1059.001, T1027"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/asyncrat_yara_patterns.md"

    strings:
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $val = "Windows Security Update" ascii
        $ps1 = "powershell -nop -w hidden -e " ascii
        $cmd1 = "cmd /c start" ascii

    condition:
        2 of ($reg, $val, $ps1, $cmd1)
}
