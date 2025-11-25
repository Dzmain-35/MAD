rule Mal_CarnavalHeist
{
meta:
    description = "Identifies CarnavalHeist Latin malware"
strings: 
    $str1 = "4.203.136.169"
	$str2 = "NotaFiscal.pdf"
	$str3 = ".brazilsouth.cloudapp.azure.com"
	$str4 = "NWljbUY2YVd4emIzVjBhQzVqYkc5MVpHRndjQzVoZW5WeVpTNWpiMjB"
	$str5 = "146.75.28.223"
	$str6 = "80\\Documentos" 
condition:
 2 of them
    
}