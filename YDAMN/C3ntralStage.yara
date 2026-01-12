import "pe"

rule Mal_Datto_RMM
{
meta:
	description = "Identifies CentraStage/Datto RMM malware"
strings: 
    $str1 = "CentraStage" nocase
	$str2 = "CentraStage.Cag" nocase
	$str3 = "CagService.exe" nocase
	$str4 = "datto" nocase
	$str5 = "Datto RMM Agent"
	$domain1 = "vidal-monitoring.centrastage.net"
	$domain2 = "rmm.datto.com"

condition:
  any of them
	
}


rule Mal_Datto_IMPHASH
{
    meta:
        description = "Identifies Datto RMM malware via common imphash"
        imphash = "187b3ae62ff818788b8c779ef7bc3d1c"
    condition:
        pe.imphash() == "187b3ae62ff818788b8c779ef7bc3d1c" and
        filesize > 5MB
}
