rule Mal_Fleet_Deck_RAT
{
meta:
	author = "Dmain"
	description = "Identifies Fleet Deck RAT"
strings: 
	$str1 = "FleetDeck Agent"
	
condition:
	  1 of them
}
