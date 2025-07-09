rule asyncrat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects AsyncRAT payloads using static configuration strings and mutex artifacts"
        malware_family = "AsyncRAT"
        mitre_attack = "T1059.001, T1027, T1218.005"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/asyncrat_yara_patterns.md"

    strings:
        $s1 = "AsyncRAT Server" ascii
        $s2 = "InstallPath" ascii
        $s3 = "Paste_bin" ascii
        $s4 = "Settings::StartUp" ascii
        $s5 = "System.Management.Automation" ascii wide
        $mutex = "AsyncMutex_" ascii
        $c2_marker = "client_socket.Connect" ascii

    condition:
        all of ($s*) or
        (2 of ($s*) and $mutex and filesize < 800KB)
}
