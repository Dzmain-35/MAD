rule Mal_STRRAT
{
meta:
	author = "Dmain"
	description = "Identifies STRRAT malware"
strings: 
	$str1 = "STRRAT"
	$str2 = "carLambo"
	$str3 = "RegisterClipboardFormat(Ljava/lang/String;)"
	$str4 = "HBrowserNativeApis"
	$str5 = "jbfrost.livestrigoi"
	$str6 = "Branchlock"
	$str7 = "strigoi"
	$c21 = "lastdopelast.ddns.net"
	$c22 = "mysaviourlives.ddns.net"
condition:
  any of them
	
}

rule Windows_Trojan_STRRAT_a3e48cd2 {
    meta:
        author = "Elastic Security"
        id = "a3e48cd2-e65f-40db-ab55-8015ad871dd6"
        fingerprint = "efda9a8bd5f9e227a6696de1b4ea7eb7343b08563cfcbe73fdd75164593bd111"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.STRRAT"
        reference_sample = "97e67ac77d80d26af4897acff2a3f6075e0efe7997a67d8194e799006ed5efc9"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "strigoi/server/ping.php?lid="
        $str2 = "/strigoi/server/?hwid="
    condition:
        all of them
}

rule STRRAT_14 {
   meta:
	  description = "Detects components or the presence of STRRat used in eCrime operations"
	  license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
	  author = "@CyberRaiju"
	  reference = "https://www.jaiminton.com/reverse-engineering/strrat"
	  date = "2022-05-19"
	  hash1 = "ec48d708eb393d94b995eb7d0194bded701c456c666c7bb967ced016d9f1eff5"
	  hash2 = "0A6D2526077276F4D0141E9B4D94F373CC1AE9D6437A02887BE96A16E2D864CF"
   strings:
	  $ntwk1 = "wshsoft.company" fullword ascii
	  $ntwk2 = "str-master.pw" fullword ascii
	  $ntwk3 = "jbfrost.live" fullword ascii
	  $ntwk4 = "ip-api.com" fullword ascii
	  $ntwk5 = "strigoi" fullword ascii
	  $host1 = "ntfsmgr" fullword ascii
	  $host2 = "Skype" fullword ascii
	  $host3 = "lock.file" fullword ascii
	  $rat1 = "HBrowserNativeApis" fullword ascii
	  $rat2 = "carLambo" fullword ascii
	  $rat3 = "config" fullword ascii
	  $rat4 = "loorqhustq" fullword ascii
	  
   condition:
	  filesize < 2000KB and (2 of ($ntwk*) or all of ($host*) or 2 of ($rat*))
	  
	  }