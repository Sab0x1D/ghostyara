rule cobaltstrike_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects post-exploitation behavior of Cobalt Strike including pipe, process injection, and named events"
        malware_family = "CobaltStrike"
        mitre_attack = "T1055, T1105, T1027"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/cobaltstrike_yara_patterns.md"

    strings:
        $pipe = "\\\\.\\pipe\\MSSE-"
        $event = "Global\\PostEx_Mutex" ascii
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii

    condition:
        all of them
}
