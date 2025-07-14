rule cobaltstrike_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Cobalt Strike Beacon payloads via configuration artifacts and embedded indicators"
        malware_family = "CobaltStrike"
        mitre_attack = "T1055, T1027, T1105"
        score = 92
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/cobaltstrike_yara_patterns.md"

    strings:
        $config_marker = "stage.c" ascii
        $xor_key = { 2e 63 6f 6e 66 69 67 00 }
        $malleable1 = "http-get.uri" ascii
        $malleable2 = "http-post.uri" ascii
        $malleable3 = "publickey" ascii
        $uri1 = "/submit.php" ascii
        $uri2 = "/jquery-3.3.1.min.js" ascii

    condition:
        uint16(0) == 0x5A4D and 4 of them
}
