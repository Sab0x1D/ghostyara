rule dcrat_basic
{
    meta:
        author = "Sab0x1D"
        category = "rat"
        family = "DCRat"
        type = "static"
        description = "Detects static characteristics of DCRat"
        date = "2025-07-10"
        version = "1.0"

    strings:
        $s1 = "DC-Software" ascii
        $s2 = "DCRatClient" ascii
        $s3 = "ClientInstall" ascii
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s5 = "Stub\\Config" ascii

    condition:
        all of them
}
