rule asyncrat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects AsyncRAT behavior including persistence, execution, memory strings, and mutex use"
        malware_family = "AsyncRAT"
        mitre_attack = "T1059.001, T1053.005, T1027"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/asyncrat_yara_patterns.md"

    strings:
        $ps1 = "powershell -nop -w hidden -enc" ascii
        $cmd1 = "cmd.exe /c start" ascii
        $reg1 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii
        $proc1 = "InstallUtil" ascii
        $mem1 = "AsyncRAT Server0" ascii
        $mem2 = "ExecuteCommand_Context" ascii
        $mem3 = "duckdns.org" ascii
        $exe1 = "InstallUtil.exe" ascii
        $mutex = "AsyncMutex_" ascii

    condition:
        3 of them
}
