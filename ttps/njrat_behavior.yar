rule njrat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects njRAT runtime activity including persistence and RAT behavior"
        malware_family = "njRAT"
        mitre_attack = "T1059, T1105, T1218"
        score = 87
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/njrat_yara_patterns.md"

    strings:
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $client_msg = "Client successfully connected" ascii
        $exec_cmd = "cmd.exe /c start " ascii
        $mutex = "njRAT" wide ascii
        $dotnet = "System.Reflection.Assembly" ascii

    condition:
        4 of them
}
