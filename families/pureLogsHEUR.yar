rule PureLogs_Suspect_DotNet_Stealer_Heur
{
  meta:
    author = "Sab0x1D"
    description = "Heuristic hunt for PureLogs-like .NET stealer traits"
    reference = "See blog post references on github"
    ext_ref = "https://blog.dexpose.io/purelogger-deep-analysis-evasion-data-theft-and-encryption-mechanism/"
    date = "2025-08-26"

  strings:
    $s_vm_wmi      = "Win32_ComputerSystem" ascii wide
    $s_rm1         = "RmStartSession" ascii
    $s_rm2         = "RmRegisterResources" ascii
    $s_rm3         = "RmGetList" ascii
    $s_geo         = "ip-api.com/json" ascii
    $s_discordldb  = "\\discord\\Local Storage\\leveldb" ascii
    $s_loginData   = "\\Login Data" ascii
    $s_cookies     = "\\Network\\Cookies" ascii
    $s_filezilla   = "recentservers.xml" ascii
    $s_elevmoniker = "Elevation:Administrator!new:" ascii

    // Campaign-specific strings (update per intel):
    $s_mutex_hint  = "FQBnanyetMxSRRO" ascii
    $s_reg_once    = "Software\\IqswyHgVpagFHxu" ascii

  condition:
    // 0x5A4D = ASCII "MZ" .. the magic header for Windows PE executables (EXE, DLL, etc.)
    (uint16(0) == 0x5A4D) and 10 of ($s*)
}


// This makes the rule heuristic: instead of firing on a single string (which could cause false positives), it requires multiple independent traits plus the PE check.