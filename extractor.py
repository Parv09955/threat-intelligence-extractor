import re
import spacy

# Loading the pre-trained English model from spaCy
nlp = spacy.load("en_core_web_sm")

# A small-scale dictionary for known Malware and Threat Actors
THREAT_TERMS = {
    "MALWARE": [
        # Ransomware
        "WannaCry", "LockBit", "Ryuk", "REvil", "Conti",
        "BlackCat", "ALPHV", "Black Basta", "Maze",
        "Petya", "NotPetya", "CryptoLocker", "Cerber",
        "Hive", "Clop", "Akira", "Royal", "RansomHub",
        "DarkSide", "SamSam", "Bad Rabbit", "Phobos",

        # Banking trojans and information stealers
        "Emotet", "TrickBot", "Zeus", "Dridex", "QakBot",
        "Qbot", "IcedID", "BazarLoader", "Bumblebee",
        "Agent Tesla", "RedLine Stealer", "Raccoon Stealer",
        "Lumma Stealer", "FormBook", "Lokibot", "Ursnif",
        "AsyncRAT", "Remcos", "njRAT", "DarkComet",

        # Worms and destructive malware
        "Conficker", "Stuxnet", "Code Red", "SQL Slammer",
        "ILOVEYOU", "Mydoom", "Sasser", "Blaster",
        "Melissa", "Morris Worm", "Shamoon", "Wiper",

        # Remote access trojans and backdoors
        "BlackEnergy", "PlugX", "Poison Ivy", "Gh0st RAT",
        "Cobalt Strike", "Quasar RAT", "XtremeRAT",
        "njRAT", "DarkComet", "NetWire",

        # Botnets
        "Mirai", "Emotet", "TrickBot", "Necurs",
        "GameOver Zeus", "Cutwail", "Gafgyt", "Mozi",
        "QakBot", "Andromeda",

        # Spyware and surveillance malware
        "Pegasus", "FinFisher", "FinSpy", "DarkHotel",
        "GravityRAT", "FlexiSPY",

        # Mobile malware
        "FluBot", "Joker", "Anubis", "Cerberus",
        "TeaBot", "Octo", "Xenomorph", "HummingBad",

        # Other well-known malware
        "Zeus Panda", "Dridex", "Raspberry Robin",
        "SocGholish", "SmokeLoader", "Andromeda",
        "Turla", "XLoader", "Remcos RAT", "Gh0st RAT",
    ],

    "THREAT_ACTOR": [
        "APT1", "APT28", "APT29", "APT32", "APT33",
        "APT34", "APT35", "APT38", "APT39", "APT41",
        "Lazarus Group", "Fancy Bear", "Cozy Bear",
        "Sandworm", "Equation Group", "Turla",
        "Kimsuky", "FIN7", "FIN8", "Carbanak",
        "Scattered Spider", "Volt Typhoon",
        "Midnight Blizzard", "MuddyWater",
        "Charming Kitten", "Palo Alto Unit 42",
    ],
}


# Formats for IP Addresses and CVE identifiers
IP_PATTERN = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
)

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE
)


def valid_ipv4(value):
    # Validating an IPv4 address after pattern matching
    parts = value.split(".")
    return (
        len(parts) == 4
        and all(part.isdigit() for part in parts)
        and all(0 <= int(part) <= 255 for part in parts)
    )


def extract_indicators(text):
    results = []

    def add_entity(value, category):
        results.append({
            "Entity": value,
            "Category": category
        })

    # Extracting valid IPv4 addresses
    for match in IP_PATTERN.findall(text):
        if valid_ipv4(match):
            add_entity(match, "IP_ADDRESS")

    # Extracting CVE identifiers
    for match in CVE_PATTERN.findall(text):
        add_entity(match.upper(), "CVE_IDENTIFIERS")

    # Extracting known malware and threat actor names first
    known_threat_terms = set()

    for category, terms in THREAT_TERMS.items():
        for term in terms:
            pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"

            if re.search(pattern, text, re.IGNORECASE):
                add_entity(term, category)
                known_threat_terms.add(term.lower())

    # Applying generic Named Entity Recognition
    doc = nlp(text)

    for ent in doc.ents:
        if ent.label_ not in ("PERSON", "ORGANIZATION"):
            continue

        entity_text = ent.text.strip()

        # Skipping CVE identifiers incorrectly classified by spaCy
        if re.search(
                r"\bCVE-\d{4}-\d{4,}\b",
                entity_text,
                re.IGNORECASE
        ):
            continue

        # Skipping valid IPv4 addresses incorrectly classified by spaCy
        if valid_ipv4(entity_text):
            continue

        # Skipping entities matching known threat terms
        if any(
                re.search(
                    r"(?<!\w)" + re.escape(term) + r"(?!\w)",
                    entity_text,
                    re.IGNORECASE
                )
                for term in known_threat_terms
        ):
            continue

        add_entity(entity_text, ent.label_)

    # Removing duplicate entity-category pairs
    unique_results = []
    seen = set()

    for item in results:
        key = (item["Entity"].lower(), item["Category"])

        if key not in seen:
            seen.add(key)
            unique_results.append(item)

    return unique_results