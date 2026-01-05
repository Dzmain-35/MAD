rule Mal_ImmyBot
{
meta:
    description = "Identifies ImmyBot malware"
strings: 
    $str1 = "Immybot.Agent" 
    $str2 = "Immybot.Agent.dll" 
    $ip1= "135.234.240.83"

condition:
  any of them
    
}
