rule Mal_Grandoreiro {
    meta:
        description = "Identifies Grandoreiro malware"
    strings: 
        $str1 = "Binary.EoAKtlbmxJOYOsaVKGCVNhNF.dll"
    
    condition:
        any of them
}
