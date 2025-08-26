import "pe"

rule PureLogs_Weighted_Heuristic
{
  meta:
    author      = "Sab0x1D"
    family      = "PureLogs / PureLog Stealer"
    description = "Weighted heuristic: anti-analysis, browser loot paths, geo, RM APIs, COM elevation"
    confidence  = "hunting"
    date        = "2025-08-26"

  strings:
    // ---------- CORE (must strongly anchor to family behavior) ----------
    $c_geo      = "ip-api.com/json" ascii wide nocase
    $c_rm1      = "RmStartSession" ascii wide
    $c_rm2      = "RmRegisterResources" ascii wide
    $c_rm3      = "RmGetList" ascii wide
    $c_elev     = "Elevation:Administrator!new:" ascii wide

    // ---------- HIGH-VALUE (stealer targets / techniques) ----------
    $h_ch_key   = "\\Local State" ascii wide nocase
    $h_ch_pwd   = "\\Login Data" ascii wide nocase
    $h_ch_ck    = "\\Network\\Cookies" ascii wide nocase
    $h_discord  = "\\discord\\Local Storage\\leveldb" ascii wide nocase
    $h_filezilla= "recentservers.xml" ascii wide nocase
    $h_wmi_manu = "Win32_ComputerSystem" ascii wide   // VM/vendor probe
    $h_mutex    = "Mutex" ascii wide                   // generic hint (will pair with others)

    // ---------- OPTIONAL (anti-analysis, tooling, misc traits) ----------
    $o_vmware   = "VMware" ascii wide
    $o_vbox     = "VirtualBox" ascii wide
    $o_sbie1    = "SbieCtrl" ascii wide
    $o_sbie2    = "SbieDll.dll" ascii wide
    $o_dbg1     = "x32dbg" ascii wide
    $o_dbg2     = "x64dbg" ascii wide
    $o_ida      = "IDA" ascii wide
    $o_fiddler  = "Fiddler" ascii wide
    $o_burp     = "Burp Suite" ascii wide
    $o_wshark   = "Wireshark" ascii wide
    $o_prhack   = "ProcessHacker" ascii wide
    $o_rdp      = "TerminalServerSession" ascii wide
    $o_hwids    = "HWID" ascii wide
    $o_tg1      = "\\tdata" ascii wide
    $o_aes      = "AES-256-CBC" ascii wide
    $o_pbkdf2   = "PBKDF2" ascii wide
    $o_dpapi1   = "CryptUnprotectData" ascii wide
    $o_dpapi2   = "CryptProtectData" ascii wide

  condition:
    // PE check + reasonable size cap for userland stealers
    uint16(0) == 0x5A4D and filesize < 20MB
    // Weighted buckets
    and 1 of ($c_*)
    and 3 of ($h_*)
    and 4 of ($o_*)
    // (Optional) If present, lean on DPAPI imports — ignore if .NET stubbed:
    and (
         not pe.is_pe
         or pe.number_of_imports == 0
         or pe.imports("advapi32.dll", "CryptUnprotectData")
         or pe.imports("advapi32.dll", "CryptProtectData")
        )
}

// It splits indicators into core, high-value, and optional buckets, then requires: PE file and 1 of core and 3 of high and 4 of optional (plus a sane size cap). Tweak thresholds per your noise level.

// Precision vs recall: Core items (geo API, Restart Manager, COM elevation) are hard to fake together.
// Resilience to mutation: Even if a few strings change, the bucket thresholds still trip on behavior clusters.
// Noise control: Start with 1+3+4; if it’s too quiet, lower optional to 3. Too noisy? Raise high-value to 4.
