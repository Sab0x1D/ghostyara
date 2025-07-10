rule venomrat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects VenomRAT payloads using known mutex, network, and stub config strings"
        malware_family = "VenomRAT"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/venomrat_yara_patterns.md"

    strings:
        $mutex = "Mutex_" ascii
        $str1 = "VenomRAT" ascii
        $str2 = "System.Net.Sockets" ascii
        $str3 = "client connected" ascii
        $str4 = "InstallPath" ascii
        $str5 = "StubSettings" ascii
        $str6 = "GetHwid" ascii
        $str7 = "venomsoftware" ascii
        $cmd = "powershell -nop -w hidden" ascii

    condition:
        uint16(0) == 0x5A4D and 4 of ($mutex, $str*, $cmd)
}
