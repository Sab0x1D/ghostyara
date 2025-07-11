rule lodarat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects LodaRAT based on known static artifacts, strings, and filenames"
        malware_family = "LodaRAT"
        score = 75

    strings:
        $str1 = "WinData" ascii
        $str2 = "Chrome.exe" ascii
        $str3 = "172.111.138.100" ascii
        $str4 = "Mr. 3amo" ascii
        $str5 = "wscript.exe" ascii
        $str6 = "AutoIt" ascii
        $str7 = "New Resigned Contract" wide

    condition:
        4 of them
}
