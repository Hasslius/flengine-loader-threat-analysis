rule Suspicious_FLEngine_Evasive_Loader {
    meta:
        description = "Detects trojanized FLEngine_x64.dll with high entropy overlay and evasion artifacts"
        author = "Threat Research"
        date = "2026-10-11"
        sample_sha256 = "85cc415bb094e8af2bb0bf27fb7d2021cdb9424c516be1f11282b57ee1ee5fdf"
        mitre_att_ck = "T1574, T1106, T1055, T1027"

    strings:
        $dll_target1 = "QuickFontCache_x64.dll" ascii wide
        $dll_target2 = "dsp_ippv2_x64.dll" ascii wide
        $dll_target3 = "Blend2D.dll" ascii wide
        $manifest1   = "FLEngine_x64.dll.manifest" ascii wide

    condition:
        uint16(0) == 0x5A4D and                         // MZ Header
        uint32(uint32(0x3C)) == 0x00004550 and           // PE Signature
        filesize > 20MB and filesize < 32MB and          // Characteristic bloated size
        3 of ($dll_target*) and
        $manifest1
}
