"""Moteur de règles de Bastion : modèle, validation et compilation.

Le moteur ne touche pas au système : il transforme une configuration
(règles ordonnées, zones, réglages) en commandes nftables (Linux) ou
netsh (Windows). Tout champ venant de l'interface est validé strictement
avant d'être placé dans une commande.
"""
import ipaddress
import re
import uuid

PROTOCOLS = ["any", "tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp"]
DIRECTIONS = ["in", "out", "both"]
ACTIONS = ["allow", "block"]

DEFAULT_SETTINGS = {
    "policy_in": "block",        # block | allow
    "policy_out": "allow",       # allow | block
    "stealth": True,             # blocage silencieux (drop) + ping entrant ignoré
    "loopback": True,            # toujours autoriser la boucle locale
    "base_rules": True,          # DHCP, IPv6 ND (Linux)
    "log_blocked": True,         # journaliser les paquets bloqués
    "rollback_seconds": 30,      # 0 = pas de retour automatique
    "alerts": True,              # détecter les nouvelles applications (Windows)
    "password_hash": None,
    "password_salt": None,
}

_NAME_BAD = re.compile(r"[\x00-\x1f\x7f\"'`$\\|&;<>^%]")
_PATH_BAD = re.compile(r"[\x00-\x1f\x7f\"<>|*?]")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$|^\d{1,10}$")


class ValidationError(ValueError):
    pass


def new_id():
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------- validation
def parse_ports(text):
    """'80, 443, 1000-2000' -> [(80,80),(443,443),(1000,2000)]"""
    text = (text or "").strip()
    if not text:
        return []
    out = []
    for tok in re.split(r"[,\s;]+", text):
        if not tok:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:[-:](\d{1,5}))?", tok)
        if not m:
            raise ValidationError(f"Port invalide : « {tok} »")
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        if not (1 <= a <= 65535 and 1 <= b <= 65535) or a > b:
            raise ValidationError(f"Port ou plage hors limites : « {tok} » (1 à 65535)")
        out.append((a, b))
    return out


def ports_to_str(ports):
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ports)


def parse_addrs(text):
    """Liste d'IP, CIDR ou plages 'a-b'. Retourne [(texte_normalisé, famille)]."""
    text = (text or "").strip()
    if not text:
        return []
    out = []
    for tok in re.split(r"[,\s;]+", text):
        if not tok:
            continue
        try:
            if "-" in tok:
                a, b = tok.split("-", 1)
                ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
                if ia.version != ib.version or int(ia) > int(ib):
                    raise ValueError
                out.append((f"{ia}-{ib}", ia.version))
            elif "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                out.append((str(net), net.version))
            else:
                ip = ipaddress.ip_address(tok)
                out.append((str(ip), ip.version))
        except ValueError:
            raise ValidationError(f"Adresse IP invalide : « {tok} »")
    return out


def parse_macs(text):
    """'AA-BB-CC-DD-EE-FF, aa:bb:...' -> ['aa:bb:cc:dd:ee:ff', ...]"""
    text = (text or "").strip()
    if not text:
        return []
    out = []
    for tok in re.split(r"[,\s;]+", text):
        if not tok:
            continue
        t = tok.lower().replace("-", ":")
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", t):
            raise ValidationError(f"Adresse MAC invalide : « {tok} » (format AA:BB:CC:DD:EE:FF)")
        if t not in out:
            out.append(t)
    return out


def clean_name(name, default="Règle"):
    name = _NAME_BAD.sub("", str(name or "")).strip()[:60]
    return name or default


def normalize_rule(raw):
    """Valide et normalise une règle. Lève ValidationError."""
    if not isinstance(raw, dict):
        raise ValidationError("Règle invalide")
    r = {}
    r["id"] = re.sub(r"[^a-z0-9]", "", str(raw.get("id") or "").lower())[:12] or new_id()
    r["name"] = clean_name(raw.get("name"))
    r["enabled"] = bool(raw.get("enabled", True))
    r["action"] = raw.get("action", "block")
    r["direction"] = raw.get("direction", "out")
    r["protocol"] = str(raw.get("protocol", "any")).lower()
    if r["action"] not in ACTIONS:
        raise ValidationError("Action invalide (allow/block)")
    if r["direction"] not in DIRECTIONS:
        raise ValidationError("Direction invalide (in/out/both)")
    if r["protocol"] not in PROTOCOLS:
        raise ValidationError("Protocole invalide")
    r["local_ports"] = ports_to_str(parse_ports(raw.get("local_ports")))
    r["remote_ports"] = ports_to_str(parse_ports(raw.get("remote_ports")))
    if (r["local_ports"] or r["remote_ports"]) and r["protocol"] not in ("any", "tcp", "udp"):
        raise ValidationError("Les ports ne s'appliquent qu'à TCP, UDP (ou « tous »)")
    r["local_ip"] = ",".join(a for a, _ in parse_addrs(raw.get("local_ip")))
    r["remote_ip"] = ",".join(a for a, _ in parse_addrs(raw.get("remote_ip")))
    r["mac"] = ",".join(parse_macs(raw.get("mac")))
    if r["mac"] and r["remote_ip"]:
        raise ValidationError("Choisissez soit une adresse MAC distante, soit une adresse IP distante, pas les deux")
    for k in ("icmp_type", "icmp_code"):
        v = str(raw.get(k, "")).strip()
        if v:
            if not v.isdigit() or int(v) > 255:
                raise ValidationError("Type/code ICMP : nombre de 0 à 255")
            if r["protocol"] not in ("icmp", "icmpv6"):
                raise ValidationError("Type/code ICMP : protocole ICMP requis")
        r[k] = v
    app = str(raw.get("app", "")).strip()
    if app and _PATH_BAD.search(app):
        raise ValidationError("Chemin d'application invalide")
    r["app"] = app[:260]
    user = str(raw.get("user", "")).strip()
    if user and not _USER_RE.match(user):
        raise ValidationError("Nom d'utilisateur invalide")
    r["user"] = user
    r["log"] = bool(raw.get("log", False))
    r["comment"] = _NAME_BAD.sub("", str(raw.get("comment", "")))[:200]
    return r


def normalize_zone(raw):
    z = {
        "id": re.sub(r"[^a-z0-9]", "", str(raw.get("id") or "").lower())[:12] or new_id(),
        "name": clean_name(raw.get("name"), "Zone"),
        "addresses": ",".join(a for a, _ in parse_addrs(raw.get("addresses"))),
        "trust": raw.get("trust", "trusted"),
        "enabled": bool(raw.get("enabled", True)),
    }
    if z["trust"] not in ("trusted", "blocked"):
        raise ValidationError("Zone : « trusted » ou « blocked »")
    if not z["addresses"]:
        raise ValidationError("Zone : au moins une adresse ou un réseau")
    return z


def normalize_settings(raw, current=None):
    s = dict(DEFAULT_SETTINGS)
    if current:
        s.update(current)
    for k, v in (raw or {}).items():
        if k in ("password_hash", "password_salt"):
            continue
        if k in DEFAULT_SETTINGS:
            s[k] = v
    if s["policy_in"] not in ("block", "allow") or s["policy_out"] not in ("block", "allow"):
        raise ValidationError("Politique par défaut invalide")
    for k in ("stealth", "loopback", "base_rules", "log_blocked", "alerts"):
        s[k] = bool(s[k])
    try:
        s["rollback_seconds"] = max(0, min(300, int(s["rollback_seconds"])))
    except (TypeError, ValueError):
        raise ValidationError("Délai de retour automatique invalide")
    return s


# ---------------------------------------------------------------- expansion
def _expand(rule, resolver=None, native_in=False):
    """Une règle -> (atomes, notes). Un atome = direction/protocole/famille uniques.

    Adresse MAC : `native_in` (Linux) la compare directement à l'entrée (ether saddr).
    Sinon (sortie, ou Windows qui n'a aucun filtre MAC) elle est convertie en adresses IP
    d'après la table de voisinage (ARP) au moment de l'application.
    """
    dirs = ["in", "out"] if rule["direction"] == "both" else [rule["direction"]]
    has_ports = bool(rule["local_ports"] or rule["remote_ports"])
    protos = ["tcp", "udp"] if rule["protocol"] == "any" and has_ports else [rule["protocol"]]
    la = parse_addrs(rule["local_ip"])
    ra_base = parse_addrs(rule["remote_ip"])
    macs = parse_macs(rule.get("mac"))
    notes, atoms = [], []
    resolved = None
    if macs and resolver:
        ips = []
        for m in macs:
            ips += resolver(m)
        resolved = parse_addrs(",".join(dict.fromkeys(ips)))
    for d in dirs:
        native = bool(macs) and native_in and d == "in"
        ra = ra_base
        if macs and not native:
            if not resolved:
                notes.append("adresse MAC introuvable dans la table ARP (l'appareil doit être connecté au réseau local)")
                continue
            ra = resolved
        fams = {f for _, f in la} | {f for _, f in ra}
        if rule["protocol"] == "icmp":
            fams = {4} if not fams else fams & {4}
        elif rule["protocol"] == "icmpv6":
            fams = {6} if not fams else fams & {6}
        for p in protos:
            for fam in (sorted(fams) if fams else [None]):
                l = [a for a, f in la if fam is None or f == fam]
                r = [a for a, f in ra if fam is None or f == fam]
                if (la and not l) or (ra and not r):
                    continue
                atoms.append({"dir": d, "proto": p, "fam": fam, "laddr": l, "raddr": r, "rule": rule,
                              "mac": macs if native else []})
    if macs and not native_in and resolved:
        notes.append("filtrage MAC converti en adresses IP actuelles (Windows ne filtre pas les MAC)")
    return atoms, notes


# ---------------------------------------------------------------- Linux / nft
def _nft_set(items):
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _nft_ports(text):
    items = [p for p in text.split(",") if p]
    return _nft_set(items)


def _uid_of(user):
    if user.isdigit():
        return int(user)
    try:
        import pwd
        return pwd.getpwnam(user).pw_uid
    except Exception:
        return None


def _nft_atom(a, verdict_block):
    r = a["rule"]
    parts = []
    d, p, fam = a["dir"], a["proto"], a["fam"]
    ipk = "ip6" if fam == 6 else "ip"
    if d == "in":
        raddr_k, laddr_k, lport_k, rport_k = "saddr", "daddr", "dport", "sport"
    else:
        raddr_k, laddr_k, lport_k, rport_k = "daddr", "saddr", "sport", "dport"
    if a.get("mac"):
        parts.append(f"ether saddr {_nft_set(a['mac'])}")
    if a["raddr"]:
        parts.append(f"{ipk} {raddr_k} {_nft_set(a['raddr'])}")
    if a["laddr"]:
        parts.append(f"{ipk} {laddr_k} {_nft_set(a['laddr'])}")
    if fam and not a["raddr"] and not a["laddr"]:
        parts.append(f"meta nfproto ipv{fam}")
    if p in ("tcp", "udp"):
        pp = []
        if r["local_ports"]:
            pp.append(f"{p} {lport_k} {_nft_ports(r['local_ports'])}")
        if r["remote_ports"]:
            pp.append(f"{p} {rport_k} {_nft_ports(r['remote_ports'])}")
        parts.extend(pp or [f"meta l4proto {p}"])
    elif p in ("icmp", "icmpv6"):
        if r["icmp_type"] or r["icmp_code"]:
            if r["icmp_type"]:
                parts.append(f"{p} type {r['icmp_type']}")
            if r["icmp_code"]:
                parts.append(f"{p} code {r['icmp_code']}")
        else:
            parts.append("meta l4proto " + ("icmp" if p == "icmp" else "ipv6-icmp"))
    elif p in ("igmp", "gre", "esp"):
        parts.append(f"meta l4proto {p}")
    if r["user"]:
        uid = _uid_of(r["user"])
        if uid is None:
            return None, f"utilisateur « {r['user']} » introuvable"
        parts.append(f"meta skuid {uid}")
    if r["log"]:
        tag = re.sub(r"[^A-Za-z0-9 _.-]", "", r["name"])[:24]
        parts.append(f'log prefix "BASTION {"BLOCK" if r["action"] == "block" else "ALLOW"} {tag}: "')
    parts.append(verdict_block if r["action"] == "block" else "accept")
    return " ".join(parts), None


def compile_linux(cfg, resolver=None):
    s = cfg["settings"]
    warnings, status = [], {}
    drop = "drop" if s["stealth"] else "reject"
    lines = ["add table inet bastion", "delete table inet bastion", "table inet bastion {"]
    chains = {}
    for chain, hook, pol in (("input", "input", s["policy_in"]), ("output", "output", s["policy_out"])):
        body = []
        body.append("ct state invalid drop")
        if s["loopback"]:
            body.append("meta iif lo accept" if chain == "input" else "meta oif lo accept")
        body.append("ct state established,related accept")
        if s["base_rules"]:
            if chain == "input":
                body.append("udp sport 67 udp dport 68 accept comment \"DHCP\"")
                body.append("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit } accept")
            else:
                body.append("udp sport 68 udp dport 67 accept comment \"DHCP\"")
                body.append("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
        chains[chain] = (hook, pol, body)
    in_body, out_body = chains["input"][2], chains["output"][2]

    for z in cfg["zones"]:
        if not z["enabled"]:
            continue
        v4 = [a for a, f in parse_addrs(z["addresses"]) if f == 4]
        v6 = [a for a, f in parse_addrs(z["addresses"]) if f == 6]
        verdict = "accept" if z["trust"] == "trusted" else drop
        for fam, items in (("ip", v4), ("ip6", v6)):
            if items:
                in_body.append(f"{fam} saddr {_nft_set(items)} {verdict}")
                out_body.append(f"{fam} daddr {_nft_set(items)} {verdict}")

    for rule in cfg["rules"]:
        rid = rule["id"]
        if not rule["enabled"]:
            status[rid] = "désactivée"
            continue
        if rule["app"] and not rule["user"]:
            status[rid] = "ignorée : filtrage par exécutable impossible sous Linux (utiliser « utilisateur »)"
            warnings.append(f"« {rule['name']} » : sous Linux le filtrage par programme n'est pas disponible, indiquez un utilisateur à la place.")
            continue
        ok = 0
        atoms, notes = _expand(rule, resolver, native_in=True)
        notes = [n for n in notes if "converti" not in n]
        for a in atoms:
            text, err = _nft_atom(a, drop)
            if err:
                notes.append(err)
                continue
            if a["dir"] == "in" and rule["user"]:
                notes.append("l'utilisateur ne peut être filtré qu'en sortie")
                continue
            (in_body if a["dir"] == "in" else out_body).append(text)
            ok += 1
        status[rid] = "appliquée" if ok else "ignorée : " + ("; ".join(notes) or "aucun paquet concerné")
        if not ok:
            warnings.append(f"« {rule['name']} » : {status[rid]}")

    if s["stealth"]:
        in_body.append("icmp type echo-request drop")
        in_body.append("icmpv6 type echo-request drop")
    if s["log_blocked"]:
        if s["policy_in"] == "block":
            in_body.append('limit rate 10/second log prefix "BASTION BLOCK in: "')
        if s["policy_out"] == "block":
            out_body.append('limit rate 10/second log prefix "BASTION BLOCK out: "')

    for chain, (hook, pol, body) in chains.items():
        verdict = "accept" if pol == "allow" else "drop"
        lines.append(f"  chain {chain} {{")
        lines.append(f"    type filter hook {hook} priority 0; policy {verdict};")
        for b in body:
            lines.append("    " + b)
        lines.append("  }")
    lines.append("}")
    return {"os": "linux", "script": "\n".join(lines) + "\n", "commands": [], "warnings": warnings, "status": status}


# ---------------------------------------------------------------- Windows / netsh
def _netsh_proto(a):
    p, r = a["proto"], a["rule"]
    if p == "any":
        return "any"
    if p in ("tcp", "udp"):
        return p.upper()
    if p in ("icmp", "icmpv6"):
        base = "icmpv4" if p == "icmp" else "icmpv6"
        if r["icmp_type"] or r["icmp_code"]:
            return f"{base}:{r['icmp_type'] or 'any'},{r['icmp_code'] or 'any'}"
        return base
    return {"igmp": "2", "gre": "47", "esp": "50"}[p]


def compile_windows(cfg, resolver=None):
    s = cfg["settings"]
    warnings, status, cmds = [], {}, []
    pin = "blockinbound" if s["policy_in"] == "block" else "allowinbound"
    pout = "blockoutbound" if s["policy_out"] == "block" else "allowoutbound"
    cmds.append({"label": "Nettoyage des anciennes règles Bastion", "kind": "ps",
                 "args": ["Get-NetFirewallRule -DisplayName 'Bastion::*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"]})
    cmds.append({"label": "Activer le pare-feu et définir la politique par défaut", "kind": "netsh",
                 "args": ["advfirewall", "set", "allprofiles", "state", "on"]})
    cmds.append({"label": "Politique par défaut", "kind": "netsh",
                 "args": ["advfirewall", "set", "allprofiles", "firewallpolicy", f"{pin},{pout}"]})
    if s["log_blocked"]:
        cmds.append({"label": "Journaliser les connexions bloquées", "kind": "netsh",
                     "args": ["advfirewall", "set", "allprofiles", "logging", "droppedconnections", "enable"]})
        cmds.append({"label": "Taille du journal", "kind": "netsh",
                     "args": ["advfirewall", "set", "allprofiles", "logging", "maxfilesize", "4096"]})
    counter = [0]

    def add(label, action, direction, proto, lports="", rports="", laddr="", raddr="", program=""):
        counter[0] += 1
        args = ["advfirewall", "firewall", "add", "rule", f"name=Bastion::{counter[0]:03d}::{label[:40]}",
                f"dir={direction}", f"action={action}", f"protocol={proto}", "enable=yes", "profile=any"]
        if lports:
            args.append(f"localport={lports}")
        if rports:
            args.append(f"remoteport={rports}")
        if laddr:
            args.append(f"localip={laddr}")
        if raddr:
            args.append(f"remoteip={raddr}")
        if program:
            args.append(f"program={program}")
        cmds.append({"label": label, "kind": "netsh", "args": args})

    if s["stealth"]:
        add("Ignorer le ping entrant", "block", "in", "icmpv4:8,any")
        add("Ignorer le ping IPv6 entrant", "block", "in", "icmpv6:128,any")
    for z in cfg["zones"]:
        if not z["enabled"]:
            continue
        act = "allow" if z["trust"] == "trusted" else "block"
        for d in ("in", "out"):
            add(f"Zone {z['name']}", act, d, "any", raddr=z["addresses"])
    for rule in cfg["rules"]:
        rid = rule["id"]
        if not rule["enabled"]:
            status[rid] = "désactivée"
            continue
        if rule["user"] and not rule["app"]:
            status[rid] = "ignorée : filtrage par utilisateur non disponible sous Windows"
            warnings.append(f"« {rule['name']} » : {status[rid]}")
            continue
        n = 0
        atoms, notes = _expand(rule, resolver)
        if notes:
            warnings.extend(f"« {rule['name']} » : {t}" for t in notes)
        for a in atoms:
            add(rule["name"], "allow" if rule["action"] == "allow" else "block", a["dir"], _netsh_proto(a),
                rule["local_ports"], rule["remote_ports"], ",".join(a["laddr"]), ",".join(a["raddr"]), rule["app"])
            n += 1
        status[rid] = "appliquée" if n else "ignorée : aucun paquet concerné"
    if any(r["enabled"] and r["action"] == "allow" for r in cfg["rules"]) and any(
            r["enabled"] and r["action"] == "block" for r in cfg["rules"]):
        warnings.append("Windows : un blocage l'emporte toujours sur une autorisation, quel que soit l'ordre des règles (limite du pare-feu Windows).")
    return {"os": "windows", "script": "", "commands": cmds, "warnings": warnings, "status": status}


def compile_config(cfg, os_name, resolver=None):
    return compile_linux(cfg, resolver) if os_name == "linux" else compile_windows(cfg, resolver)
