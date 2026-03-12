rule Detect_Nivdort_DU {
    meta:
        description = "TrojanSpy:Win32_Nivdort.DU detection rules"
        date = "2026-03-12"
        version = "1.0"

    strings:
        $copyright = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED."
        $cpp_iterator = "managed vector copy constructor iterator"
        $dll_dotnet = "mscoree.dll" ascii wide
        $sys_root = "SystemRoot" ascii wide
        $cmd = "cmd.exe" ascii wide
        $debug = "IsDebuggerPresent" ascii
        $features = "IsProcessorFeaturePresent" ascii

    condition:
        // Marcador de ejecutable Windows (MZ)
        uint16(0) == 0x5A4D and
	(3 of ($copyright, $cpp_iterator, $dll_dotnet, $sys_root, $cmd, $debug, $features))
}
