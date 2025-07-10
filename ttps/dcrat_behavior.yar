rule dcrat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects DcRAT behavior based on registry keys, process traits, and memory strings"
        malware_family = "DcRAT"
        mitre_attack = "T1053.005, T1547.001, T1071.001"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/dcrat_yara_patterns.md"

    strings:
        $cmd = "cmd.exe /c start" ascii
        $reg = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide
        $mutex = "DCRAT_MUTEX" ascii
        $ps = "powershell -nop -w hidden -enc" ascii
        $util = "InstallUtil" ascii

        $mem1 = "dcrat" ascii
        $mem2 = "MUTEX" ascii
        $mem3 = "Server 1" ascii
        $mem4 = "duckdns" ascii nocase
        $mem5 = "qwqdanchun" ascii nocase

    condition:
        2 of ($cmd, $reg, $mutex, $ps, $util) or any of ($mem*)
}
