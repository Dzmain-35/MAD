rule Mal_Gorelo_RMM
{
meta:
	description = "Identifies Gorelo RMM abused malware"
strings: 
  $str1 = "GoreloInstaller"
	$str2 = "Gorelo.RemoteManagement"
	$domain1 = "gorelo.tech"
	$domain3 = "600c23d50c6ee4462ecb200a47f6b627.r2.cloudflarestorage.com"
	$domain2 = "185.90.14.232"

condition:
  any of them
	
}
