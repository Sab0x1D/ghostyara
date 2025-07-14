rule bbtok_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects BBTok Banking Trojan via known strings, overlays, and mutex"
        malware_family = "BBTok"
        mitre_attack = "T1055, T1566.001, T1566.002"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/bbtok_yara_patterns.md"

    strings:
        $s1 = "Insira seu CPF" ascii wide
        $s2 = "Santander Empresas" ascii wide
        $s3 = "Bradesco Net Empresa" ascii wide
        $s4 = "Banco do Brasil" ascii wide
        $s5 = "Itaú Empresas" ascii wide
        $mutex1 = "Global\\BBTOK_MUTEX" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*) or $mutex1
}
