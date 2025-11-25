rule Mal_Miradore_RAT
{
meta:
	description = "Identifies Miradore RAT malware"
strings: 
    $str1 = "MiradoreClient"
	$str2 = "Binary.ClientInstallerCustomActions.CA.dll"
	$str3 = "Miradore Online Client"
	$domain2 = "miradore-wekeup.service.signalr.net"
	$domain3 = "gerwconline.blob.core.windows.net"
	$domain4 = "stmiradorepatchprod.blob.core.windows.net"
	$c2_1 = "20.38.118.132"
	$c2_2 = "52.146.136.38"
	$c2_3 = "51.116.145.33"

condition:
  any of them
	
}

