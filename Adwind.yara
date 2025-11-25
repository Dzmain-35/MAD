rule Mal_Adwind
{
meta:
	description = "Identifies Adwind malware"
strings: 
	$str1 = "Modulo32.jpg"
	$str2 = "llIIIlIlIllIlII.class"
	$str3 = "Imagem.jpg"
	$str4 = "IIllIlI/lIlIIlIlIl/IIlIlIlIIl/lIllIlIIlI/lIIIIIIlIIlIllIIl.classPK"
	$c21 = "3.tcp.ngrok.io"
	$c22 = "3.130.209.29"
	$c23 = "13.59.222.135 "
	$c24= "office.smokebombz.com"
	$c25 = "dollypopo.hopto.org"
	$c26 = "147.124.209.46"
condition:
  any of them
	
}



