#!/usr/bin/env python3
"""Point d'entrée de Bastion.

  python pare_feu.py                lance l'interface (navigateur)
  python pare_feu.py --apply        applique la configuration enregistrée puis quitte
                                   (pour un lancement au démarrage)
  python pare_feu.py --simulate     force le mode simulation (aucune règle réelle)
  python pare_feu.py --no-browser   n'ouvre pas le navigateur, affiche seulement le lien
"""
import argparse
import sys

from bastion import server, system


def main():
    ap = argparse.ArgumentParser(description="Bastion — pare-feu personnel Windows/Linux")
    ap.add_argument("--apply", action="store_true", help="applique la configuration enregistrée et quitte")
    ap.add_argument("--simulate", action="store_true", help="mode simulation")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--port", type=int, default=0)
    a = ap.parse_args()

    if a.apply:
        store = system.Store()
        events = system.EventLog()
        fw = system.Firewall(store, events, simulate=a.simulate or None)
        if fw.simulate:
            print("Droits administrateur requis pour appliquer les règles.")
            return 1
        store.cfg["settings"]["rollback_seconds"] = 0
        res = fw.apply()
        print("OK" if res["ok"] else "ÉCHEC : " + " | ".join(res["errors"]))
        for w in res["warnings"]:
            print("Avertissement :", w)
        return 0 if res["ok"] else 2
    return server.serve(simulate=True if a.simulate else None, open_browser=not a.no_browser, port=a.port)


if __name__ == "__main__":
    sys.exit(main())
