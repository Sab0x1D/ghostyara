rule netsupport_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects NetSupport Manager client implants via static file markers and INI configuration strings"
        malware_family = "NetSupport Manager"
        mitre_attack = "T1219, T1105"
        score = 75
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/netsupport_yara_patterns.md"

    strings:
        $mz = { 4D 5A }
        $client_ini = "client32.ini" ascii
        $str1 = "[Client]" ascii
        $str2 = "Name=" ascii
        $str3 = "GatewayAddress=" ascii
        $str4 = "GatewayPort=" ascii
        $str5 = "ConnectivityMode=" ascii
        $str6 = "LoggingLevel=" ascii
        $str7 = "InstallPath=" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($client_ini, $str1, $str2, $str3, $str4, $str5, $str6, $str7)
}
