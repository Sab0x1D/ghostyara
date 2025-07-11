rule Mispadu_Basic_Static_Indicators
{
    meta:
        author = "Sab0x1D"
        family = "Mispadu"
        type = "static"
        description = "Detects static strings and patterns associated with Mispadu stealer"
        created = "2025-07-11"

    strings:
        $vbs_ext = ".vbs"
        $hta_ext = ".hta"
        $autoit_marker = "AutoIt v3 Script has stopped working"
        $host_server = "host.secureserver.net"
        $pastebin = "pastebin.com/raw"
        $pastery = "pastery.net"
        $glitch = "glitch[.]me"

    condition:
        2 of them
}
