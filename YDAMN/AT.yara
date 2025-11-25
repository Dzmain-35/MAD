rule Mal_AgentTesla
{
meta:
	author = "Dmain"
	description = "Identifies AgentTesla malware"
strings: 
	$str1 = "profiles.ini"
	$str2 = "User Data"
	$str4 = "https://dokdo.in/TUK"
	$str5 = "fridayyyyvert.3utilities.com"
	$str6 = "198.54.116.140"
	$str7 = "173.231.16.76"
	$str8 = "181.131.217.94"
	$str9 = "149.154.167.220"
	$str10 = "89.238.66.41"
	$str11 = "208.95.112.1"
	$str12 = "149.154.167.220"
	$str13 = "172.67.74.152"
	$str14 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0"
	$url1 = "api.ipify.org"
	$url2 = "https://api.telegram.org/bot7000875199:AAGcJDBHFcfVUBvhBO4xZLw34OXk1NWXSe0/"
	$url3 = "biz@ctdi.com.ph"
	
	
condition:
	  3 of them
}


rule Windows_Trojan_AgentTesla_e577e17e {
    meta:
        author = "Elastic Security"
        id = "e577e17e-5c42-4431-8c2d-0c1153128226"
        fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_f2a90d14 {
    meta:
        author = "Elastic Security"
        id = "f2a90d14-7212-41a5-a2cd-a6a6dedce96e"
        fingerprint = "829c827069846ba1e1378aba8ee6cdc801631d769dc3dce15ccaacd4068a88a6"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_a2d69e48 {
    meta:
        author = "Elastic Security"
        id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
        fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
        creation_date = "2023-05-01"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
        $a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_ebf431a8 {
    meta:
        author = "Elastic Security"
        id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
        fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
        creation_date = "2023-12-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "MozillaBrowserList"
        $a2 = "EnableScreenLogger"
        $a3 = "VaultGetItem_WIN7"
        $a4 = "PublicIpAddressGrab"
        $a5 = "EnableTorPanel"
        $a6 = "get_GuidMasterKey"
    condition:
        4 of them
}


