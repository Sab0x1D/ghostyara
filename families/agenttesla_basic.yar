rule agenttesla_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects Agent Tesla payloads using configuration strings, SMTP IOCs, and mutex artifacts"
        malware_family = "AgentTesla"
        mitre_attack = "T1056.001, T1113, T1005"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/agenttesla_yara_patterns.md"

    strings:
        $mutex1 = "Mutex__Agt" ascii
        $config1 = "UseSmtpSSL" ascii
        $config2 = "HostName" ascii
        $url1 = "smtp.yandex.com" ascii
        $url2 = "smtp.office365.com" ascii
        $b64marker = "TVqQAAMAAAAEAAAA" ascii  // base64-encoded 'MZ'
        $http1 = "POST /api/addlog" ascii wide
        $net = "System.Net.Mail" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        4 of ($mutex1, $config*, $url*, $b64marker, $http1)
}
