rule cobaltstrike_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-15"
        description = "Detects Cobalt Strike deployment via ISO > LNK > PowerShell beacon chain"
        malware_family = "CobaltStrike"
        mitre_attack = "T1204, T1059.001, T1566.001, T1221"
        score = 93
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/cobaltstrike_yara_patterns.md"

    strings:
        $lnk = /\.lnk$/ nocase
        $ps1 = "powershell -nop -w hidden" ascii
        $url = "http://127.0.0.1" ascii
        $iso = /\.iso$/ nocase
        $whoami = "whoami" ascii

    condition:
        all of ($lnk, $ps1, $iso) and any of ($url, $whoami)
}
