import requests
import sys

def getthq(thqmd5):
    thquser = "088611ff43c14dcbb8ce10af714872b4"
    thqpass = "5ea7fba6ebff4158a0469b47a49c2895"
    url = f"https://www.threathq.com/apiv1/threat/search/?malwareArtifactMD5={thqmd5}"
    response = requests.post(url, auth=(thquser, thqpass))
    return response

def parse_family_name(response):
    try:
        data = response.json()
        threats = data.get("data", {}).get("threats", [])
        for threat in threats:
            block_set = threat.get("blockSet", [])
            for block in block_set:
                malware_family = block.get("malwareFamily", {})
                family_name = malware_family.get("familyName")
                if family_name:
                    return family_name
        return "Unknown"
    except (ValueError, KeyError) as e:
        return f"Error parsing response: {e}"

# Example usage
if __name__ == "__main__":
    md5_hash = sys.argv[1].strip()
    response = getthq(md5_hash)

    if response.status_code == 200:
        family_name = parse_family_name(response)
        print(f"Family: {family_name}")
    else:
        print(f"Error: {response.status_code}\n{response.text}")
