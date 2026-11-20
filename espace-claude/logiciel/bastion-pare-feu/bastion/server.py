"""Serveur local (127.0.0.1) : interface web + API JSON de Bastion."""
import copy
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import engine, system
from .library import LIBRARY

if getattr(sys, "frozen", False):  # exécutable PyInstaller
    WEB_DIR = os.path.join(sys._MEIPASS, "web")
else:
    WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


def open_url(url):
    """Ouvre le navigateur ; sous Linux lancé en root via sudo, l'ouvre avec le compte d'origine."""
    try:
        if os.name != "nt" and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
            import subprocess
            subprocess.Popen(["sudo", "-u", os.environ["SUDO_USER"], "xdg-open", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(url)
    except Exception:
        pass


class App:
    def __init__(self, simulate=None):
        self.store = system.Store()
        self.events = system.EventLog()
        self.fw = system.Firewall(self.store, self.events, simulate)
        self.alerts = system.AlertWatcher(self.store, self.events)
        self.token = secrets.token_urlsafe(24)
        self.unlocked = not self.store.cfg["settings"].get("password_hash")
        self.port = 0

    # ---- vues
    def public_settings(self):
        s = dict(self.store.cfg["settings"])
        s["has_password"] = bool(s.pop("password_hash", None))
        s.pop("password_salt", None)
        return s

    def state(self):
        cfg = self.store.cfg
        comp = self.fw.compile()
        return {
            "version": system.VERSION, "os": system.OS_NAME, "admin": system.is_admin(),
            "simulate": self.fw.simulate, "active": self.fw.active, "applied_at": self.fw.applied_at,
            "dirty": cfg.get("applied_hash") != self.store.digest(),
            "pending_seconds": self.fw.pending_seconds(),
            "settings": self.public_settings(), "rules": cfg["rules"], "zones": cfg["zones"],
            "profiles": sorted(cfg["profiles"].keys()), "active_profile": cfg.get("active_profile", ""),
            "status": comp["status"], "warnings": comp["warnings"],
            "alerts_supported": system.OS_NAME == "windows",
        }

    # ---- modifications
    def set_all(self, body):
        with self.store.lock:
            cfg = self.store.cfg
            errors = {}
            if "rules" in body:
                rules = []
                for i, r in enumerate(body["rules"][:500]):
                    try:
                        rules.append(engine.normalize_rule(r))
                    except engine.ValidationError as e:
                        errors[str(i)] = str(e)
                if errors:
                    return {"ok": False, "errors": errors}
                cfg["rules"] = rules
            if "zones" in body:
                zones = []
                for i, z in enumerate(body["zones"][:100]):
                    try:
                        zones.append(engine.normalize_zone(z))
                    except engine.ValidationError as e:
                        return {"ok": False, "errors": {"zone": str(e)}}
                cfg["zones"] = zones
            if "settings" in body:
                try:
                    cfg["settings"] = engine.normalize_settings(body["settings"], cfg["settings"])
                except engine.ValidationError as e:
                    return {"ok": False, "errors": {"settings": str(e)}}
            self.store.save()
        return {"ok": True}

    def profile_op(self, op, name):
        name = engine.clean_name(name, "Profil")
        cfg = self.store.cfg
        if op == "save":
            snap = {k: copy.deepcopy(cfg[k]) for k in ("rules", "zones")}
            snap["settings"] = {k: v for k, v in cfg["settings"].items() if not k.startswith("password")}
            cfg["profiles"][name] = snap
            cfg["active_profile"] = name
        elif op == "load" and name in cfg["profiles"]:
            p = cfg["profiles"][name]
            cfg["rules"] = [engine.normalize_rule(r) for r in p["rules"]]
            cfg["zones"] = [engine.normalize_zone(z) for z in p["zones"]]
            cfg["settings"] = engine.normalize_settings(p["settings"], cfg["settings"])
            cfg["active_profile"] = name
        elif op == "delete":
            cfg["profiles"].pop(name, None)
            if cfg.get("active_profile") == name:
                cfg["active_profile"] = ""
        else:
            return {"ok": False, "error": "Profil introuvable"}
        self.store.save()
        return {"ok": True}

    def import_config(self, body):
        try:
            rules = [engine.normalize_rule(r) for r in body.get("rules", [])[:500]]
            zones = [engine.normalize_zone(z) for z in body.get("zones", [])[:100]]
        except engine.ValidationError as e:
            return {"ok": False, "error": str(e)}
        mode = body.get("mode", "append")
        if mode == "replace":
            self.store.cfg["rules"] = rules
            self.store.cfg["zones"] = zones
        else:
            existing = {r["id"] for r in self.store.cfg["rules"]}
            for r in rules:
                if r["id"] in existing:
                    r["id"] = engine.new_id()
            self.store.cfg["rules"].extend(rules)
        self.store.save()
        return {"ok": True, "count": len(rules)}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Bastion"

        def log_message(self, *a):
            pass

        # -- utilitaires
        def _send(self, code, body, ctype="application/json", headers=None):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") or ctype == "application/json" else ""))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, ensure_ascii=False))

        def _host_ok(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            return host in ("127.0.0.1", "localhost")

        def _cookie_ok(self):
            c = self.headers.get("Cookie") or ""
            m = re.search(r"(?:^|;\s*)bst=([^;]+)", c)
            return bool(m) and secrets.compare_digest(m.group(1), app.token)

        def _api_ok(self):
            return self._host_ok() and self._cookie_ok() and self.headers.get("X-Bastion") == "1"

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return {}

        # -- GET
        def do_GET(self):
            if not self._host_ok():
                return self._send(403, "Hôte refusé", "text/plain")
            u = urlparse(self.path)
            if u.path == "/" or u.path == "/index.html":
                q = parse_qs(u.query)
                hdr = {}
                if q.get("t", [""])[0] == app.token:
                    hdr["Set-Cookie"] = f"bst={app.token}; HttpOnly; SameSite=Strict; Path=/"
                    if app.store.cfg["settings"].get("password_hash"):
                        app.unlocked = False
                    return self._send(302, "", "text/plain", {**hdr, "Location": "/"})
                if not self._cookie_ok():
                    return self._send(403, "Lancez Bastion pour obtenir un lien d'accès valide.", "text/plain")
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html")
            if u.path.startswith("/static/"):
                name = os.path.basename(u.path)
                p = os.path.join(WEB_DIR, name)
                if os.path.isfile(p):
                    ct = mimetypes.guess_type(p)[0] or "application/octet-stream"
                    with open(p, "rb") as f:
                        return self._send(200, f.read(), ct)
                return self._send(404, "introuvable", "text/plain")
            if not u.path.startswith("/api/"):
                return self._send(404, "introuvable", "text/plain")
            if not self._api_ok():
                return self._json({"error": "accès refusé"}, 403)
            if u.path == "/api/session":
                return self._json({"unlocked": app.unlocked, "has_password": bool(app.store.cfg["settings"].get("password_hash"))})
            if not app.unlocked:
                return self._json({"error": "verrouillé"}, 401)
            if u.path == "/api/state":
                return self._json(app.state())
            if u.path == "/api/library":
                return self._json([e for e in LIBRARY if e["os"] in (None, system.OS_NAME)])
            if u.path == "/api/library/all":
                return self._json(LIBRARY)
            if u.path == "/api/preview":
                comp = app.fw.compile()
                if comp["os"] == "linux":
                    text = "# nftables — script appliqué par Bastion\n" + comp["script"]
                else:
                    text = "\n".join(
                        ("PowerShell> " + c["args"][0]) if c["kind"] == "ps" else ("netsh " + " ".join(_q(a) for a in c["args"]))
                        for c in comp["commands"])
                return self._json({"text": text, "warnings": comp["warnings"]})
            if u.path == "/api/connections":
                rows = system.list_connections()
                return self._json({"rows": rows, "demo": False})
            if u.path == "/api/log":
                rows, note = system.read_firewall_log()
                demo = False
                if not rows and app.fw.simulate:
                    rows, demo = system.demo_log(), True
                return self._json({"rows": rows, "note": note, "demo": demo, "events": app.events.tail(100)[::-1]})
            if u.path == "/api/alerts":
                return self._json(app.alerts.list())
            if u.path == "/api/export":
                cfg = app.store.cfg
                return self._json({"format": "bastion-rules", "version": 1, "rules": cfg["rules"], "zones": cfg["zones"]})
            return self._json({"error": "route inconnue"}, 404)

        # -- POST
        def do_POST(self):
            if not (self._api_ok()):
                return self._json({"error": "accès refusé"}, 403)
            p = urlparse(self.path).path
            body = self._body()
            if p == "/api/login":
                if system.check_password(app.store.cfg["settings"], body.get("password", "")):
                    app.unlocked = True
                    return self._json({"ok": True})
                return self._json({"ok": False, "error": "Mot de passe incorrect"}, 401)
            if p == "/api/lock":
                app.unlocked = not app.store.cfg["settings"].get("password_hash")
                return self._json({"ok": True})
            if not app.unlocked:
                return self._json({"error": "verrouillé"}, 401)
            if p == "/api/save":
                return self._json(app.set_all(body))
            if p == "/api/apply":
                return self._json(app.fw.apply())
            if p == "/api/confirm":
                return self._json({"ok": app.fw.confirm()})
            if p == "/api/revert":
                ok, msg = app.fw.revert()
                return self._json({"ok": ok, "msg": msg})
            if p == "/api/disable":
                app.fw.disable()
                return self._json({"ok": True})
            if p == "/api/profile":
                return self._json(app.profile_op(body.get("op"), body.get("name", "")))
            if p == "/api/import":
                return self._json(app.import_config(body))
            if p == "/api/password":
                s = app.store.cfg["settings"]
                if not system.check_password(s, body.get("old", "")):
                    return self._json({"ok": False, "error": "Ancien mot de passe incorrect"}, 401)
                new = body.get("new", "")
                if new:
                    if len(new) < 4:
                        return self._json({"ok": False, "error": "4 caractères minimum"})
                    s["password_hash"], s["password_salt"] = system.hash_password(new)
                else:
                    s["password_hash"] = s["password_salt"] = None
                app.store.save()
                return self._json({"ok": True})
            if p == "/api/alerts/resolve":
                try:
                    app.alerts.resolve(body.get("app", ""))
                    if body.get("decision") in ("allow", "block") and body.get("app"):
                        r = engine.normalize_rule({
                            "name": os.path.basename(body["app"]) or "Application", "action": body["decision"],
                            "direction": "both", "protocol": "any", "app": body["app"], "log": body["decision"] == "block"})
                        app.store.cfg["rules"].append(r)
                        app.store.save()
                except engine.ValidationError as e:
                    return self._json({"ok": False, "error": str(e)})
                return self._json({"ok": True})
            return self._json({"error": "route inconnue"}, 404)

    return Handler


def _q(a):
    return f'"{a}"' if " " in a else a


def serve(simulate=None, open_browser=True, port=0):
    app = App(simulate)
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    app.port = srv.server_address[1]
    url = f"http://127.0.0.1:{app.port}/?t={app.token}"
    app.alerts.start()
    print("=" * 60)
    print(f" Bastion Pare-feu {system.VERSION} — {system.OS_NAME}")
    print(f" Droits administrateur : {'oui' if system.is_admin() else 'NON'}"
          f"{'  → mode SIMULATION (aucune règle réelle appliquée)' if app.fw.simulate else ''}")
    print(f" Interface : {url}")
    print(" (Ctrl+C pour quitter ; les règles appliquées restent actives)")
    print("=" * 60)
    if open_browser:
        threading.Timer(0.6, lambda: open_url(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt de l'interface.")
    return 0
