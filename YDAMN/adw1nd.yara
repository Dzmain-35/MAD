rule Mal_Adwind
{
meta:
	description = "Identifies Adwind malware"
strings: 
	$str1 = "Modulo32.jpg"
	$str2 = "llIIIlIlIllIlII.class"
	$str3 = "Imagem.jpg"
	$c21 = "3.tcp.ngrok.io"
	$c22 = "3.130.209.29"
	$c23 = "13.59.222.135 "
	$c24= "office.smokebombz.com"
condition:
  any of them
	
}



