rule cobaltstrike_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-15"
        description = "Detects embedded Cobalt Strike beacons using config markers and payload characteristics"
        malware_family = "CobaltStrike"
        mitre_attack = "T1055, T1071, T1027"
        score = 88
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/cobaltstrike_yara_patterns.md"

    strings:
        $cfg = "stage.cleanup" ascii
        $http = "GET /" ascii
        $powershell = "powershell -nop -w hidden" wide
        $pipe = "\\\\.\\pipe\\msagent_" ascii
        $malleable = "Malleable_C2" ascii
        $cc2 = "cobaltstrike" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of them
}
