"""Bibliothèque de règles prêtes à l'emploi (équivalent de la « bibliothèque de règles » de Look 'n' Stop).

Chaque entrée : groupe, description, règle. `os` limite l'exemple à un système.
"""


def _r(name, action, direction, protocol="any", lp="", rp="", lip="", rip="", app="", user="", it="", ic="", log=False, comment="", mac=""):
    return {"name": name, "action": action, "direction": direction, "protocol": protocol,
            "local_ports": lp, "remote_ports": rp, "local_ip": lip, "remote_ip": rip,
            "app": app, "user": user, "mac": mac, "icmp_type": it, "icmp_code": ic, "log": log, "comment": comment,
            "enabled": True}


LIBRARY = [
    # --- Navigation et services courants
    {"group": "Navigation & services", "title": "Web sortant (HTTP/HTTPS)", "os": None,
     "desc": "Laisse votre PC consulter des sites web. Ports distants 80 et 443 en TCP.",
     "rule": _r("Web sortant", "allow", "out", "tcp", rp="80,443")},
    {"group": "Navigation & services", "title": "DNS (résolution de noms)", "os": None,
     "desc": "Indispensable quand la sortie est bloquée par défaut : sans DNS, plus aucun nom de site ne fonctionne.",
     "rule": _r("DNS sortant", "allow", "out", "udp", rp="53")},
    {"group": "Navigation & services", "title": "DNS en TCP", "os": None,
     "desc": "Certaines réponses DNS longues passent en TCP.",
     "rule": _r("DNS TCP sortant", "allow", "out", "tcp", rp="53")},
    {"group": "Navigation & services", "title": "Heure réseau (NTP)", "os": None,
     "desc": "Synchronisation de l'horloge.",
     "rule": _r("NTP sortant", "allow", "out", "udp", rp="123")},
    {"group": "Navigation & services", "title": "Courrier chiffré (SMTP/IMAP/POP3 sécurisés)", "os": None,
     "desc": "Ports 465, 587, 993 et 995.",
     "rule": _r("Mail sécurisé", "allow", "out", "tcp", rp="465,587,993,995")},
    {"group": "Navigation & services", "title": "Courrier non chiffré (25, 110, 143)", "os": None,
     "desc": "À bloquer en priorité sur un réseau public : le contenu circule en clair.",
     "rule": _r("Mail non chiffré", "block", "out", "tcp", rp="25,110,143")},
    {"group": "Navigation & services", "title": "FTP client", "os": None,
     "desc": "Ports 20 et 21 en sortie ; les clients doivent utiliser le mode passif (PASV).",
     "rule": _r("FTP client", "allow", "out", "tcp", rp="20,21")},

    # --- Ports ouverts (serveurs)
    {"group": "Ports ouverts (serveur)", "title": "Serveur web local (80/443)", "os": None,
     "desc": "Ouvre les ports 80 et 443 en entrée pour héberger un site.",
     "rule": _r("Serveur web", "allow", "in", "tcp", lp="80,443")},
    {"group": "Ports ouverts (serveur)", "title": "SSH depuis le réseau local seulement", "os": None,
     "desc": "Port 22 ouvert uniquement pour 192.168.0.0/16 : le reste d'Internet n'y accède pas.",
     "rule": _r("SSH réseau local", "allow", "in", "tcp", lp="22", rip="192.168.0.0/16")},
    {"group": "Ports ouverts (serveur)", "title": "Home Assistant (8123) depuis le LAN", "os": None,
     "desc": "Autorise l'interface web de Home Assistant, uniquement depuis votre réseau privé.",
     "rule": _r("Home Assistant", "allow", "in", "tcp", lp="8123", rip="192.168.0.0/16")},
    {"group": "Ports ouverts (serveur)", "title": "Serveur Minecraft (25565)", "os": None,
     "desc": "Port TCP 25565 entrant.",
     "rule": _r("Minecraft", "allow", "in", "tcp", lp="25565")},
    {"group": "Ports ouverts (serveur)", "title": "Plage de ports (exemple 5000-5100)", "os": None,
     "desc": "Une plage s'écrit « début-fin ». Ici UDP 5000 à 5100 entrant.",
     "rule": _r("Plage UDP 5000-5100", "allow", "in", "udp", lp="5000-5100")},

    # --- Ports fermés (blocages)
    {"group": "Ports fermés (blocage)", "title": "Bloquer Telnet (23)", "os": None,
     "desc": "Telnet transmet les mots de passe en clair : fermez-le.",
     "rule": _r("Bloquer Telnet", "block", "both", "tcp", lp="23", log=True)},
    {"group": "Ports fermés (blocage)", "title": "Bloquer le partage Windows (135, 139, 445)", "os": None,
     "desc": "Ferme SMB/NetBIOS en entrée : vecteur classique des vers et rançongiciels.",
     "rule": _r("Bloquer SMB entrant", "block", "in", "tcp", lp="135,139,445", log=True)},
    {"group": "Ports fermés (blocage)", "title": "Bloquer le Bureau à distance (3389)", "os": None,
     "desc": "RDP exposé sur Internet est très attaqué.",
     "rule": _r("Bloquer RDP", "block", "in", "tcp", lp="3389", log=True)},
    {"group": "Ports fermés (blocage)", "title": "Bloquer BitTorrent (6881-6889)", "os": None,
     "desc": "Ports classiques du pair-à-pair.",
     "rule": _r("Bloquer BitTorrent", "block", "both", "any", lp="6881-6889")},
    {"group": "Ports fermés (blocage)", "title": "Bloquer une adresse IP", "os": None,
     "desc": "Remplacez 203.0.113.50 par l'adresse à bloquer (entrée et sortie).",
     "rule": _r("Bloquer 203.0.113.50", "block", "both", "any", rip="203.0.113.50", log=True)},

    # --- Adresse MAC
    {"group": "Adresse MAC (appareil)", "title": "Bloquer un appareil par son adresse MAC", "os": None,
     "desc": "Coupe tout échange avec un appareil précis du réseau local (téléphone, console…). Remplacez l'adresse d'exemple. L'adresse MAC se lit dans les réglages de l'appareil ou dans « arp -a ».",
     "rule": _r("Bloquer appareil AA:BB:CC:DD:EE:FF", "block", "both", "any", mac="aa:bb:cc:dd:ee:ff", log=True)},
    {"group": "Adresse MAC (appareil)", "title": "SSH autorisé uniquement depuis mon PC (MAC)", "os": None,
     "desc": "Port 22 ouvert pour une seule machine du réseau, reconnue à son adresse MAC. À placer avant une règle qui bloque SSH.",
     "rule": _r("SSH depuis mon PC (MAC)", "allow", "in", "tcp", lp="22", mac="aa:bb:cc:dd:ee:ff")},

    # --- ICMP
    {"group": "ICMP (ping)", "title": "Autoriser mon ping sortant", "os": None,
     "desc": "ICMP type 8 (echo-request) vers l'extérieur : vous pouvez tester les machines distantes.",
     "rule": _r("Ping sortant", "allow", "out", "icmp", it="8")},
    {"group": "ICMP (ping)", "title": "Refuser le ping entrant", "os": None,
     "desc": "Personne ne peut « voir » votre machine par ping (mode furtif).",
     "rule": _r("Ping entrant bloqué", "block", "in", "icmp", it="8")},
    {"group": "ICMP (ping)", "title": "ICMP type 3 code 4 (fragmentation)", "os": None,
     "desc": "Message « fragmentation nécessaire » : à laisser passer pour que les gros paquets fonctionnent.",
     "rule": _r("ICMP 3/4", "allow", "in", "icmp", it="3", ic="4")},

    # --- Applications
    {"group": "Applications", "title": "Autoriser Firefox (Windows)", "os": "windows",
     "desc": "Programme autorisé en sortie sur les ports web.",
     "rule": _r("Firefox", "allow", "out", "tcp", rp="80,443", app=r"C:\Program Files\Mozilla Firefox\firefox.exe")},
    {"group": "Applications", "title": "Autoriser Chrome (Windows)", "os": "windows",
     "desc": "Chrome en sortie sur les ports web.",
     "rule": _r("Chrome", "allow", "out", "tcp", rp="80,443", app=r"C:\Program Files\Google\Chrome\Application\chrome.exe")},
    {"group": "Applications", "title": "Bloquer un programme (Windows)", "os": "windows",
     "desc": "Interdit toute communication d'un programme (adaptez le chemin).",
     "rule": _r("Bloquer un programme", "block", "both", "any", app=r"C:\Program Files\MonLogiciel\logiciel.exe", log=True)},
    {"group": "Applications", "title": "Bloquer Internet à un utilisateur (Linux)", "os": "linux",
     "desc": "Sous Linux le filtrage se fait par compte : ici le compte « invite » ne peut plus rien envoyer.",
     "rule": _r("Bloquer l'utilisateur invite", "block", "out", "any", user="invite", log=True)},
    {"group": "Applications", "title": "Autoriser le compte www-data à sortir sur le web (Linux)", "os": "linux",
     "desc": "Utile si la sortie est bloquée par défaut : le compte du serveur web peut joindre les ports 80/443.",
     "rule": _r("Web sortant www-data", "allow", "out", "tcp", rp="80,443", user="www-data")},
]
