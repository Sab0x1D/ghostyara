rule mispadu_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Mispadu payloads using static string markers and C2 patterns"
        malware_family = "Mispadu"
        mitre_attack = "T1059.005, T1055.001, T1566"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/mispadu_c2_patterns.md"

    strings:
        $artifact1 = "AutoIt v3 Script has stopped working" ascii
        $artifact2 = "Introduzca la contrasena" ascii
        $artifact3 = ".hta" ascii
        $artifact4 = ".vbs" ascii
        $artifact5 = "C:\\Users\\Public" ascii

        $net1 = "host.secureserver.net" ascii
        $net2 = /hxxps?:\/\/[0-9a-zA-Z\[\]]{5,30}\.host\.secureserver\.net/ ascii
        $net3 = /[0-9]{1,3}(\.[0-9]{1,3}){3}/ ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($artifact*) and 1 of ($net*)
}
