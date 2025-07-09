rule agent_tesla_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-09"
        description = "Detects AgentTesla stealer using static strings and mutex patterns"
        malware_family = "AgentTesla"
        mitre_attack = "T1056.001, T1113, T1005"
        reference = ""
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/agenttesla_c2_patterns.md"

    strings:
        $mutex1 = "Mutex__Agt" ascii
        $config1 = "UseSmtpSSL" ascii
        $config2 = "HostName" ascii
        $url1 = "smtp.yandex.com" ascii
        $url2 = "smtp.office365.com" ascii
        $b64marker = "TVqQAAMAAAAEAAAA" ascii  // MZ header in base64
        $http1 = "POST /api/addlog" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        4 of ($mutex1, $config*, $url*, $b64marker, $http1)
}
