rule Mal_Mekotio
{
meta:
	description = "Identifies Metamorfo/mekotio Brazillian malware"
strings:
	$str1 = "194.36.90.111"
	$str2 = "ip: 188.241.177.202"
	$str3 = "/contadores/"
	$str4 = "https://ipinfo.io/missingauth"
	$str5 = "Binary.aicustact.dll"
	$str6 = "libeay32.dll"
	$str7 = "Binary.SoftwareDetector.dll"
	$c2_1 = "tudoprafrente.org"
condition:
	2 of them
	
}

rule Mal_Ousaban 
{
meta:
	describtion = "Identifies Ousaban Metamorfo/mekotio variant"
strings:
	$str1 = "StarBurn.dll"
	$str2 = "Drivespan.dll"
	$str3 = "disk1.cab"
	$str4 = "Binary.aicustact.dll"
	$str5 = "G2MInstaller.exe"
	$str6 = "inspecionando.php"
	$str7 = "chrome_elf.dll"
	$c21 = "142.171.227.163"
	$c22 = "zanottorefeicoes.com.br"
	$c23 = "52.201.255.221"
	$c24 = "23.94.168.103"
condition:
	2 of them

}

rule Mal_Ponteiro
{
meta:
	describtion = "Identifies Ponteiro Metamorfo/mekotio variant"
strings:
	$str1 = "cadastropositivo.online"
	$str2 = "xx.exe"
	$str3 = "zpresampler.dll"
	$str4 = "64.226.97.61"
	$str5 = "Fazdownload"
condition:
	2 of them


}

