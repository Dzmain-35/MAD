rule Mal_Loda_RAT
{
meta:
	description = "Identifies L0da RAT"
strings: 
	$str1 = "172.111.138.100"
	$str2 = "mp3quran.net"

condition:
  any of them
	
}


