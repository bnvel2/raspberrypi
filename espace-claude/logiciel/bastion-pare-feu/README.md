# Bastion — pare-feu personnel Windows / Linux

Bastion est un pare-feu avec une interface moderne, inspiré de **Look 'n' Stop** :
règles ordonnées, filtrage par application, bibliothèque de règles, zones, journal,
profils, mot de passe, et un menu **Aide** avec des exemples de ports ouverts/fermés
et d'applications autorisées/bloquées (chaque exemple s'ajoute en un clic).

Il ne remplace pas le moteur du système : il **pilote** le pare-feu intégré
(nftables sous Linux, Pare-feu Windows Defender sous Windows) et lui envoie des
règles propres, validées, avec retour arrière automatique.

## Lancer

| Système | Commande |
|---|---|
| **Windows** | double-clic sur `lancer_windows.bat` (demande les droits administrateur) — ou télécharger `../bastion-windows.zip` |
| **Linux** | (`../bastion-linux.zip`) `./lancer_linux.sh` (utilise sudo ; nécessite `nftables` : `sudo apt install nftables`) |

Prérequis : **Python 3.8+**. `psutil` est facultatif (installé automatiquement sous Windows ;
sous Linux : `sudo apt install python3-psutil`) et améliore la liste des connexions.

L'interface s'ouvre dans votre navigateur sur `http://127.0.0.1:<port>/`.
Sans droits administrateur, Bastion démarre en **mode simulation** : tout fonctionne
sauf l'application réelle des règles.

Option : `build_exe_windows.bat` fabrique un `Bastion.exe` autonome (PyInstaller).

## Utilisation en 3 temps
1. Créez ou importez des règles (onglet *Filtrage Internet*, bouton *Bibliothèque*).
2. **Appliquer** (en haut à droite) : les règles sont envoyées au système.
3. **Confirmer** dans le délai (30 s par défaut), sinon l'état précédent revient seul.
   *Aperçu des commandes* montre exactement ce qui sera exécuté.

## Correspondance avec Look 'n' Stop
| Look 'n' Stop | Bastion |
|---|---|
| Filtrage Internet : règles de paquets ordonnées (sens, TCP/UDP/ICMP/IGMP/GRE/ESP, IP + masque, ports égal / liste / plage, type et code ICMP) | Onglet *Filtrage Internet* : mêmes critères, IPv4 et IPv6, plages d'IP |
| Filtrage des applications | Onglet *Applications* (Windows : par programme ; Linux : par compte utilisateur) |
| Bibliothèque de règles (.rie) | *Bibliothèque* intégrée (web, DNS, mail, SSH, Home Assistant, Telnet, SMB, RDP, BitTorrent, ping…) + import/export `.json` |
| Fenêtre d'alerte « nouveau programme » | Bandeau d'alerte avec Autoriser / Bloquer / Ignorer (Windows) |
| Journal | Onglet *Journal* (paquets bloqués + événements) |
| Mot de passe | Mot de passe de l'interface (PBKDF2) |
| Mode furtif | *Options → Mode furtif* |
| Appliquer puis Enregistrer | *Appliquer* + confirmation automatique/annulation |

## Ce qui diffère (et pourquoi)
- **Windows** : le pare-feu Windows donne toujours la priorité à un blocage sur une autorisation, quel que soit l'ordre ; Bastion l'indique. La détection de nouveaux programmes se fait *après* leur première connexion (pas d'interception en temps réel : cela demande un pilote noyau signé).
- **Linux** : nftables filtre par **compte utilisateur** et non par programme. Pour isoler une application, lancez-la sous un compte dédié et bloquez ce compte. Les règles sont perdues au redémarrage : voir `extras/bastion.service` ou lancez `sudo python3 pare_feu.py --apply` au démarrage.
- Filtrage par adresse MAC : natif en entrée sous Linux ; converti en adresses IP (table ARP) en sortie sous Linux et sur Windows. Pas de drapeaux TCP pour l'instant.

## Sécurité de l'application
- Le serveur n'écoute que sur `127.0.0.1`, avec un jeton aléatoire par lancement, un contrôle de l'en-tête `Host` et un en-tête anti-CSRF.
- Tous les champs (ports, IP, noms, chemins) sont validés avant de former une commande ; aucune commande n'est exécutée via un shell.
- Les règles sont enregistrées dans `%ProgramData%\Bastion\config.json` (Windows) ou `/var/lib/bastion/config.json` (Linux, root).

## En cas de perte de connexion
Attendez la fin du compte à rebours sans confirmer, ou *Tableau de bord → Désactiver Bastion*.
Dernier recours : `sudo nft delete table inet bastion` (Linux) · `netsh advfirewall reset` (Windows).

## Tests
`python3 tests/test_engine.py` (valide aussi la syntaxe nftables si `nft` est présent).
