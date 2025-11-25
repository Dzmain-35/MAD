import "pe"

rule Mal_Byakugan
{
meta:
	description = "Identifies Byakugan malware"
strings: 
    $str1 = "BYAKUGAN"
	$str2 = "DKNBYAKUGANBYAKUGAN"
	$domain1 = "89.117.72.231"
	$domain2 = "purpleadapter.com.br"
	$domain3 = "https://89.117.72.231:8080/"
	$domain4 = "thinkforce.com.br"

condition:
  any of them
	
}

rule Byakugan2
{
    meta:
        description = "Matches files with imphash 10251855b9d0100a92e44870d4a3801c and size > 50MB"
        author = "ChatGPT"
        date = "2025-05-01"
        imphash = "10251855b9d0100a92e44870d4a3801c"

    condition:
        pe.imphash() == "10251855b9d0100a92e44870d4a3801c" and
        filesize > 50MB
}

