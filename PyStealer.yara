rule Mal_Xworm
{
meta:
	description = "Identifies Xworm malware"
strings: 
    $str1 = /_MEI.+\\Crypto\\Cipher/
	
condition:
  any of them
	
}

