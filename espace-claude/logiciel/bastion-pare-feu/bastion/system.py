"""Interaction avec le système : droits, stockage, application des règles,
connexions actives, journal du pare-feu et détection de nouvelles applications.
"""
import copy
import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import threading
import time

from . import engine

IS_WINDOWS = os.name == "nt"
OS_NAME = "windows" if IS_WINDOWS else "linux"
VERSION = "1.0.0"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def is_admin():
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def data_dir():
    base = os.environ.get("BASTION_HOME")
    if not base:
        if IS_WINDOWS:
            base = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Bastion")
        elif is_admin():
            base = "/var/lib/bastion"
        else:
            base = os.path.join(os.path.expanduser("~"), ".local", "share", "bastion")
    os.makedirs(base, exist_ok=True)
    return base


def run(cmd, input_text=None, timeout=30):
    """Exécute une commande (sans shell). Retourne (code, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"commande introuvable : {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "délai dépassé"
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


# ------------------------------------------------------------------ stockage
class Store:
    def __init__(self, path=None):
        self.path = path or os.path.join(data_dir(), "config.json")
        self.lock = threading.RLock()
        self.cfg = self._load()

    def _default(self):
        return {"version": 1, "settings": dict(engine.DEFAULT_SETTINGS), "zones": [], "rules": [],
                "profiles": {}, "active_profile": "", "applied_hash": None}

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            base = self._default()
            base.update(cfg)
            base["settings"] = engine.normalize_settings(cfg.get("settings", {}))
            if cfg.get("settings"):
                base["settings"]["password_hash"] = cfg["settings"].get("password_hash")
                base["settings"]["password_salt"] = cfg["settings"].get("password_salt")
            return base
        except FileNotFoundError:
            cfg = self._default()
            cfg["rules"] = [engine.normalize_rule(r["rule"]) for r in _starter_rules()]
            return cfg
        except Exception:
            return self._default()

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cfg, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
            if not IS_WINDOWS:
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

    def digest(self):
        c = {k: self.cfg[k] for k in ("settings", "zones", "rules")}
        c = copy.deepcopy(c)
        c["settings"].pop("password_hash", None)
        c["settings"].pop("password_salt", None)
        return hashlib.sha1(json.dumps(c, sort_keys=True).encode()).hexdigest()


def _starter_rules():
    from .library import LIBRARY
    wanted = {"Web sortant (HTTP/HTTPS)", "DNS (résolution de noms)", "Bloquer Telnet (23)",
              "Bloquer le partage Windows (135, 139, 445)", "Refuser le ping entrant"}
    return [e for e in LIBRARY if e["title"] in wanted]


# ------------------------------------------------------------------ journal interne
class EventLog:
    def __init__(self):
        self.path = os.path.join(data_dir(), "events.jsonl")
        self.lock = threading.Lock()

    def add(self, kind, message):
        rec = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "msg": message}
        with self.lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except OSError:
                pass

    def tail(self, n=200):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-n:]
            return [json.loads(l) for l in lines if l.strip()]
        except Exception:
            return []


# ------------------------------------------------------------------ voisinage (ARP) : MAC -> IP
def neighbours():
    """{mac: [ip, ...]} d'après la table ARP / de voisinage du système."""
    table = {}
    mac_re = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
    if OS_NAME == "linux":
        rc, out, _ = run(["ip", "-o", "neigh"])
        if rc != 0:
            rc, out, _ = run(["arp", "-an"])
        for ln in out.splitlines():
            m = re.search(mac_re, ln)
            tok = ln.split()
            pm = re.search(r"\(([0-9a-fA-F:.]+)\)", ln)  # format « arp -an »
            cand = pm.group(1) if pm else (tok[0] if tok else "")
            if m and re.fullmatch(r"[0-9a-fA-F:.]+", cand):
                table.setdefault(m.group(0).lower().replace("-", ":"), []).append(cand)
    else:
        rc, out, _ = run(["arp", "-a"])
        for ln in out.splitlines():
            t = ln.split()
            if len(t) >= 2 and re.fullmatch(mac_re, t[1]) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", t[0]):
                table.setdefault(t[1].lower().replace("-", ":"), []).append(t[0])
    return table


def make_resolver():
    cache = {}

    def resolve(mac):
        if not cache:
            cache.update(neighbours())
        return cache.get(mac, [])
    return resolve


# ------------------------------------------------------------------ application des règles
class Firewall:
    """Applique une configuration compilée au système (ou la simule)."""

    def __init__(self, store, events, simulate=None):
        self.store = store
        self.events = events
        self.simulate = (not is_admin()) if simulate is None else simulate
        self.sim_applied = None
        self.backup = None
        self.pending_until = None
        self._timer = None
        self.lock = threading.RLock()
        self.applied_at = None
        self.active = False

    # -- helpers
    def compile(self):
        return engine.compile_config(self.store.cfg, OS_NAME, make_resolver())

    def _backup(self):
        if self.simulate:
            self.backup = {"sim": self.sim_applied}
            return
        if OS_NAME == "linux":
            rc, out, _ = run(["nft", "list", "table", "inet", "bastion"])
            self.backup = {"nft": out if rc == 0 else None}
        else:
            path = os.path.join(data_dir(), "backup.wfw")
            rc, _, err = run(["netsh", "advfirewall", "export", path])
            self.backup = {"wfw": path if rc == 0 else None}

    def _restore(self):
        b = self.backup or {}
        if self.simulate:
            self.sim_applied = b.get("sim")
            self.active = self.sim_applied is not None
            return True, "simulation restaurée"
        if OS_NAME == "linux":
            if b.get("nft"):
                rc, _, err = run(["nft", "-f", "-"], input_text="delete table inet bastion\n" + b["nft"])
                if rc != 0:
                    run(["nft", "-f", "-"], input_text=b["nft"])
            else:
                run(["nft", "delete", "table", "inet", "bastion"])
            self.active = bool(b.get("nft"))
            return True, "état précédent restauré"
        if b.get("wfw"):
            rc, _, err = run(["netsh", "advfirewall", "import", b["wfw"]])
            self.active = False
            return rc == 0, "état précédent restauré" if rc == 0 else err
        return False, "aucune sauvegarde disponible"

    # -- actions
    def apply(self):
        with self.lock:
            comp = self.compile()
            self._cancel_timer()
            self._backup()
            errors = []
            if self.simulate:
                self.sim_applied = comp
            elif OS_NAME == "linux":
                rc, out, err = run(["nft", "-f", "-"], input_text=comp["script"])
                if rc != 0:
                    errors.append((err or out).strip())
            else:
                for c in comp["commands"]:
                    if c["kind"] == "ps":
                        rc, out, err = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", c["args"][0]])
                    else:
                        rc, out, err = run(["netsh"] + c["args"])
                    if rc != 0:
                        errors.append(f"{c['label']} : {(err or out).strip()[:200]}")
            if errors:
                self._restore()
                self.events.add("erreur", "Application échouée : " + " | ".join(errors)[:300])
                return {"ok": False, "errors": errors, "warnings": comp["warnings"], "status": comp["status"]}
            self.active = True
            self.applied_at = time.strftime("%H:%M:%S")
            self.store.cfg["applied_hash"] = self.store.digest()
            self.store.save()
            secs = self.store.cfg["settings"]["rollback_seconds"]
            if secs:
                self.pending_until = time.time() + secs
                self._timer = threading.Timer(secs, self._auto_revert)
                self._timer.daemon = True
                self._timer.start()
            self.events.add("appliqué", f"{len(self.store.cfg['rules'])} règle(s) appliquée(s)"
                            + (" (simulation)" if self.simulate else ""))
            return {"ok": True, "errors": [], "warnings": comp["warnings"], "status": comp["status"],
                    "pending_seconds": secs}

    def _cancel_timer(self):
        if self._timer:
            self._timer.cancel()
            self._timer = None
        self.pending_until = None

    def _auto_revert(self):
        with self.lock:
            self.pending_until = None
            self._restore()
            self.store.cfg["applied_hash"] = None
            self.events.add("retour auto", "Modification non confirmée : état précédent restauré")

    def confirm(self):
        with self.lock:
            self._cancel_timer()
            self.events.add("confirmé", "Application confirmée")
            return True

    def revert(self):
        with self.lock:
            self._cancel_timer()
            ok, msg = self._restore()
            self.store.cfg["applied_hash"] = None
            self.events.add("annulé", "Retour à l'état précédent : " + msg)
            return ok, msg

    def disable(self):
        with self.lock:
            self._cancel_timer()
            if self.simulate:
                self.sim_applied = None
            elif OS_NAME == "linux":
                run(["nft", "delete", "table", "inet", "bastion"])
            else:
                run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-NetFirewallRule -DisplayName 'Bastion::*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"])
                run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])
            self.active = False
            self.store.cfg["applied_hash"] = None
            self.events.add("désactivé", "Règles Bastion retirées du système")

    def pending_seconds(self):
        if self.pending_until:
            return max(0, int(self.pending_until - time.time()))
        return 0


# ------------------------------------------------------------------ connexions actives
def list_connections():
    rows = []
    try:
        import psutil
        procs = {}
        for c in psutil.net_connections(kind="inet"):
            pid = c.pid or 0
            if pid and pid not in procs:
                try:
                    p = psutil.Process(pid)
                    exe = ""
                    try:
                        exe = p.exe()
                    except Exception:
                        pass
                    procs[pid] = (p.name(), exe, p.username() if hasattr(p, "username") else "")
                except Exception:
                    procs[pid] = ("?", "", "")
            name, exe, user = procs.get(pid, ("", "", ""))
            proto = "tcp" if c.type == 1 else "udp"
            if c.family == 10 or (c.laddr and ":" in c.laddr.ip):
                proto += "6"
            rows.append({
                "proto": proto,
                "laddr": c.laddr.ip if c.laddr else "", "lport": c.laddr.port if c.laddr else 0,
                "raddr": c.raddr.ip if c.raddr else "", "rport": c.raddr.port if c.raddr else 0,
                "state": c.status if c.status != "NONE" else "", "pid": pid, "name": name, "exe": exe, "user": user})
        return rows
    except ImportError:
        pass
    except Exception:
        pass
    if OS_NAME == "linux":
        rc, out, _ = run(["ss", "-H", "-tunap"])
        for ln in out.splitlines():
            m = re.match(r"(\w+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+users:\(\(\"([^\"]*)\",pid=(\d+))?", ln)
            if not m:
                continue
            proto, state, la, ra, name, pid = m.groups()

            def sp(a):
                h, _, p = a.rpartition(":")
                return h.strip("[]"), int(p) if p.isdigit() else 0
            lh, lp = sp(la)
            rh, rp = sp(ra)
            rows.append({"proto": proto, "laddr": lh, "lport": lp,
                         "raddr": rh if rh not in ("*", "0.0.0.0", "::") else "", "rport": rp,
                         "state": state if state != "UNCONN" else "", "pid": int(pid or 0), "name": name or "", "exe": "", "user": ""})
    else:
        rc, out, _ = run(["netstat", "-ano"])
        names = {}
        rc2, tl, _ = run(["tasklist", "/FO", "CSV", "/NH"])
        for ln in tl.splitlines():
            parts = [p.strip('"') for p in ln.split('","')]
            if len(parts) > 1 and parts[1].isdigit():
                names[int(parts[1])] = parts[0].strip('"')
        for ln in out.splitlines():
            t = ln.split()
            if len(t) >= 4 and t[0] in ("TCP", "UDP"):
                def sp(a):
                    h, _, p = a.rpartition(":")
                    return h.strip("[]"), int(p) if p.isdigit() else 0
                lh, lp = sp(t[1])
                rh, rp = sp(t[2])
                pid = int(t[-1]) if t[-1].isdigit() else 0
                rows.append({"proto": t[0].lower(), "laddr": lh, "lport": lp,
                             "raddr": rh if rh not in ("*", "0.0.0.0", "::") else "", "rport": rp,
                             "state": t[3] if t[0] == "TCP" else "", "pid": pid, "name": names.get(pid, ""), "exe": "", "user": ""})
    return rows


# ------------------------------------------------------------------ journal du pare-feu
_KV = re.compile(r"(\w+)=(\S*)")


def read_firewall_log(limit=300):
    """Retourne (entrées, remarque)."""
    entries = []
    note = ""
    if OS_NAME == "linux":
        rc, out, err = run(["journalctl", "-k", "-o", "short-iso", "--no-pager", "-n", "2000", "-g", "BASTION"])
        if rc != 0:
            rc, out, err = run(["dmesg", "--time-format", "iso"])
            if rc != 0:
                return [], "Journal noyau illisible (droits administrateur requis)."
        for ln in out.splitlines():
            if "BASTION" not in ln:
                continue
            kv = dict(_KV.findall(ln))
            m = re.search(r"BASTION (BLOCK|ALLOW) ?([^:]*):", ln)
            act = "bloqué" if (m and m.group(1) == "BLOCK") else "autorisé"
            entries.append({"t": ln[:19].replace("T", " "), "action": act, "proto": kv.get("PROTO", ""),
                            "src": kv.get("SRC", ""), "sport": kv.get("SPT", ""), "dst": kv.get("DST", ""),
                            "dport": kv.get("DPT", ""), "info": (m.group(2).strip() if m else "") or kv.get("IN", "") or kv.get("OUT", "")})
    else:
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "LogFiles", "Firewall", "pfirewall.log")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-3000:]
        except OSError:
            return [], "Journal Windows introuvable : appliquez les règles (journalisation activée) puis réessayez."
        for ln in lines:
            if ln.startswith("#") or not ln.strip():
                continue
            t = ln.split()
            if len(t) >= 8:
                entries.append({"t": f"{t[0]} {t[1]}", "action": "bloqué" if t[2] == "DROP" else "autorisé",
                                "proto": t[3], "src": t[4], "sport": t[6], "dst": t[5], "dport": t[7],
                                "info": t[-1] if t[-1] in ("RECEIVE", "SEND") else ""})
    return entries[-limit:][::-1], note


def demo_log():
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    rows = [("bloqué", "TCP", "185.220.101.4", "51522", "192.168.1.20", "23", "Bloquer Telnet"),
            ("bloqué", "TCP", "45.155.205.9", "40122", "192.168.1.20", "445", "Bloquer SMB entrant"),
            ("bloqué", "ICMP", "91.121.4.18", "", "192.168.1.20", "", "Ping entrant bloqué"),
            ("bloqué", "UDP", "192.168.1.55", "5353", "192.168.1.20", "1900", "politique par défaut"),
            ("autorisé", "TCP", "192.168.1.20", "50211", "93.184.216.34", "443", "Web sortant")]
    return [{"t": now, "action": a, "proto": p, "src": s, "sport": sp, "dst": d, "dport": dp, "info": i + " (démo)"}
            for a, p, s, sp, d, dp, i in rows]


# ------------------------------------------------------------------ alertes nouvelles applications
class AlertWatcher(threading.Thread):
    """Détecte les applications qui ouvrent une connexion sortante sans règle (Windows)."""

    def __init__(self, store, events):
        super().__init__(daemon=True)
        self.store = store
        self.events = events
        self.seen = set()
        self.pending = {}
        self.lock = threading.Lock()
        self.first = True

    def known(self, exe):
        low = exe.lower()
        return any(r["app"].lower() == low for r in self.store.cfg["rules"] if r["app"])

    def run(self):
        while True:
            try:
                if OS_NAME == "windows" and self.store.cfg["settings"].get("alerts"):
                    self.scan()
            except Exception:
                pass
            time.sleep(4)

    def scan(self):
        import psutil
        for c in psutil.net_connections(kind="inet"):
            if not (c.raddr and c.pid and c.status == "ESTABLISHED"):
                continue
            if c.raddr.ip.startswith(("127.", "::1")):
                continue
            try:
                exe = psutil.Process(c.pid).exe()
            except Exception:
                continue
            if not exe or exe in self.seen:
                continue
            self.seen.add(exe)
            if self.first:  # applications déjà actives au démarrage : on les mémorise sans alerte
                continue
            if self.known(exe):
                continue
            with self.lock:
                self.pending[exe] = {"app": exe, "name": os.path.basename(exe), "raddr": c.raddr.ip,
                                     "rport": c.raddr.port, "t": time.strftime("%H:%M:%S")}
            self.events.add("alerte", f"Nouvelle application : {exe} → {c.raddr.ip}:{c.raddr.port}")
        self.first = False

    def list(self):
        with self.lock:
            return list(self.pending.values())

    def resolve(self, app):
        with self.lock:
            self.pending.pop(app, None)


# ------------------------------------------------------------------ mot de passe
def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
    return h, salt


def check_password(settings, password):
    if not settings.get("password_hash"):
        return True
    h, _ = hash_password(password or "", settings["password_salt"])
    return secrets.compare_digest(h, settings["password_hash"])
