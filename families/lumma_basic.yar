rule lumma_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Lumma Stealer payloads via hardcoded strings and C2 socket markers"
        malware_family = "Lumma Stealer"
        mitre_attack = "T1059, T1560, T1555, T1114"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/lumma_yara_patterns.md"

    strings:
        $json_header = "{\"r\":[],\"b\":[],\"g\":0}" ascii
        $str1 = "c2sock" ascii
        $str2 = "mr.temp" ascii
        $str3 = "user data" ascii
        $str4 = "local state" ascii
        $str5 = "TeslaBrowser" ascii
        $str6 = "wallets" ascii
        $str7 = "webcache" ascii
        $str8 = ".fun" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of them
}
