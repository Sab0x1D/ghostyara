rule venomrat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects VenomRAT based on hardcoded strings and static config markers"
        malware_family = "VenomRAT"
        score = 85
        version = "1.0"

    strings:
        $s1 = "VenomRAT" ascii
        $s2 = "Mutex_" ascii
        $s3 = "System.Net.Sockets" ascii
        $s4 = "client connected" ascii
        $s5 = "InstallPath" ascii
        $s6 = "StubSettings" ascii
        $s7 = "GetHwid" ascii
        $s8 = "venomsoftware" ascii
        $cmd = "powershell -nop -w hidden" ascii

    condition:
        3 of ($s*) or $cmd
}
