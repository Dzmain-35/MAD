import "pe"
rule Mal_N_AbleRAT
{
meta:
	description = "Identifies N-AbleRAT malware"
strings: 
    $str1 = "N-able Technologies"
	$str2 = "Windows Agent"
	$str3 = "msp-agent-core.msi"
	$str4 = "Advanced Monitoring Agent"
	$str5 = "upload2.am.remote.management"
	$str6 = "https://n-able.com/"


condition:
  2 of them
	
}

rule Mal_N_Able_RAT_IMPHASH
{
    meta:
        description = "Identifies N_Able RAT Imphashes"
        imphash = "0c40996f6e1e5f2a82b51e9950881bf1"
    condition:
        pe.imphash() == "0c40996f6e1e5f2a82b51e9950881bf1"
}
