import "pe"

rule Suspicious_FLEngine_Trojanised_Loader {
    meta:
        description = "Detects trojanised FL Studio audio engine DLL exhibiting packing, overlay artifacts, and loader wrapper stubs"
        author = "Threat Research"
        date = "2026-10-11"
        sample_sha256 = "85cc415bb094e8af2bb0bf27fb7d2021cdb9424c516be1f11282b57ee1ee5fdf"
        reference = "https://github.com/Hasslius/flengine-loader-threat-analysis"
        mitre_att_ck = "T1574.001, T1106, T1055, T1027"

    strings:
        // Legitimate engine strings observed in dependency probing
        $dep1 = "QuickFontCache_x64.dll" ascii wide nocase
        $dep2 = "dsp_ippv2_x64.dll" ascii wide nocase
        $dep3 = "Blend2D.dll" ascii wide nocase

        // Anomalous manifest & wrapper exports observed in sandbox execution
        $wrapper_export1 = "CreateFruityInstance" ascii
        $wrapper_export2 = "__dbk_fcall_wrapper" ascii
        $wrapper_export3 = "dbkFCallWrapperAddr" ascii
        $anom_manifest   = ".123.Manifest" ascii wide

    condition:
        // Validate 64-bit Portable Executable DLL
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.is_64bit() and
        pe.is_dll and

        // Bloated size range matching modified package
        filesize > 20MB and filesize < 32MB and

        // Dependency references present
        2 of ($dep*) and

        // Differentiating signatures: presence of anomalous export wrappers or modified manifests
        (
            2 of ($wrapper_export*) or
            $anom_manifest or
            pe.overlay.size > 1MB
        )
}
