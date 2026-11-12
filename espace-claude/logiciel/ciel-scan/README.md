# ciel-scan : scanner réseau pédagogique en Rust

Petit scanner réseau écrit **de zéro** pour le bac pro CIEL, à partir des protocoles publics
(ICMP, ARP, TCP, DNS, SNMP, SMB, Wake-on-LAN). Il ne reprend aucun code ni aucun fichier
de données d'Advanced IP Scanner ou d'un autre logiciel : il reproduit seulement le
*principe* de fonctionnement étudié en cours.

> **À n'utiliser que sur un réseau dont vous avez l'autorisation.** Par défaut, le programme
> refuse les adresses publiques (voir « Garde-fous »).

## Ce que fait le programme

| Fonction | Commande / option | Technique |
| --- | --- | --- |
| Détecter les machines | `scan <cible>` | `ping` du système + tentative de connexion TCP |
| Ports ouverts | `--ports` | connexion TCP complète, port par port |
| Nom de la machine | automatique | DNS inverse |
| Adresse MAC | automatique | ARP (Windows : `SendARP` ; Linux : cache ARP du noyau) |
| Fabricant | `--oui` | 3 premiers octets de la MAC (OUI) |
| Équipements SNMP | `--snmp [communauté]` | SNMP v2c GET de `sysName` et `sysDescr` |
| Dossiers partagés | `--partages` | `NetShareEnum` (Windows uniquement) |
| Réveil à distance | `wol <mac>` | paquet magique en diffusion UDP (port 9) |
| Export | `--csv fichier.csv` | CSV séparé par « ; », lisible par Excel |

**Volontairement absent :** l'extinction à distance de machines, le pilotage Radmin et toute
tentative de deviner des mots de passe SNMP (la communauté est celle que vous indiquez).

## Compiler

### Sous Windows (recommandé)

1. Installer Rust depuis <https://rustup.rs> (il demande aussi les « Build Tools » de Visual Studio).
2. Dans le dossier du projet :

```powershell
cargo build --release
```

Le programme est produit dans `target\release\ciel-scan.exe`. Un seul fichier, sans installation.

### Avec GitHub (sans installer Rust)

Le fichier `.github/workflows/windows.yml` fait compiler et tester le programme sur une machine
Windows de GitHub. Placez le projet dans un dépôt GitHub, ouvrez l'onglet **Actions**, lancez
« Construire ciel-scan.exe (Windows) », puis téléchargez l'artefact `ciel-scan-windows`
(il contient `ciel-scan.exe`). Les 29 tests sont exécutés sous Windows au passage.

### Depuis Linux vers Windows (non testé ici)

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu
```

## Utiliser

```powershell
# Tout un réseau /24 avec les ports par défaut
.\ciel-scan.exe scan 192.168.1.0/24

# Une plage, des ports choisis, SNMP, partages, export, base complète des fabricants
.\ciel-scan.exe scan 192.168.1.1-50 --ports 22,80,443,3389 --snmp --partages --csv resultat.csv --oui oui.csv

# Réveiller une machine (adresse de diffusion du réseau en option)
.\ciel-scan.exe wol AA:BB:CC:DD:EE:FF --diffusion 192.168.1.255
```

Formes de cible acceptées : `192.168.1.10`, `192.168.1.0/24`, `192.168.1.10-50`,
`192.168.1.10-192.168.1.20`, ou une liste séparée par des virgules. Maximum : 65 536 adresses.

### Base des fabricants

Le programme n'embarque que 7 exemples. Pour une couverture complète, téléchargez la base
publique de l'IEEE (`oui.csv` ou `oui.txt`, page « Registration Authority » de l'IEEE) ou le
fichier `manuf` de Wireshark, puis passez-le avec `--oui`.

## Garde-fous

- Seules les adresses privées (10/8, 172.16/12, 192.168/16), la boucle locale et le lien local
  sont analysées. Pour une autre adresse, il faut ajouter `--autoriser-public`, ce qui engage
  la responsabilité de l'utilisateur : scanner un réseau sans autorisation peut être un délit
  (articles 323-1 et suivants du Code pénal).
- Les textes reçus du réseau (nom SNMP, etc.) sont protégés dans le CSV contre l'injection de
  formules Excel.

## Limites connues

- L'ARP ne traverse pas les routeurs : la MAC n'est connue que pour les machines du même
  réseau local.
- Un pare-feu qui bloque ping et ports rend une machine invisible.
- Les services sont déduits du **numéro de port** seulement (pas d'analyse des réponses
  comme le fait Nmap).
- Le temps d'un scan dépend du nombre de ports et du délai (`--delai-ms`, 400 par défaut).

## Organisation du code (pour le TP)

| Fichier | Rôle | Notion du programme |
| --- | --- | --- |
| `src/cible.rs` | lecture des cibles, garde-fou | adressage IPv4, CIDR, adresses privées |
| `src/ping.rs` | test de présence | ICMP, réponse reconnue par `TTL=` |
| `src/ports.rs` | scan de ports | connexion TCP, ports bien connus |
| `src/arp.rs` | adresse MAC | ARP, couche 2 |
| `src/oui.rs` | fabricant | OUI, adresse administrée localement |
| `src/snmp.rs` | SNMP v2c | codage BER, OID, MIB-II |
| `src/shares.rs` | partages Windows | SMB, API NetShareEnum |
| `src/wol.rs` | réveil réseau | diffusion UDP, paquet magique de 102 octets |
| `src/main.rs` | ligne de commande, parallélisme | threads, export CSV |

Exercices possibles : ajouter un port au tableau des noms de services, ajouter l'OID `sysUpTime`
au SNMP, écrire un test pour une nouvelle forme de cible.

## Tests

```bash
cargo test
```

29 tests unitaires couvrent l'analyse des cibles et des ports, le codage SNMP (une requête
construite à la main octet par octet sert de référence), la lecture des bases de fabricants,
le paquet Wake-on-LAN et le cache ARP.

Le dossier `outils/` contient `faux_equipement_snmp.py`, un faux équipement SNMP écrit
indépendamment du code Rust : il vérifie que la requête est bien formée puis répond, ce qui
permet de tester `--snmp` sans matériel.

```bash
sudo python3 -I outils/faux_equipement_snmp.py &     # écoute sur 127.0.0.1:161
./target/release/ciel-scan scan 127.0.0.1 --snmp
```

## État de la validation

- Testé sous Linux : compilation, 29 tests, scan de la boucle locale (port TCP, SNMP, CSV),
  refus des adresses publiques, envoi Wake-on-LAN vérifié par un récepteur.
- Code spécifique à Windows (`SendARP`, `NetShareEnum`, affichage UTF-8 de la console) :
  la vérification de types par le compilateur passe, mais il n'a **pas été exécuté** sur Windows.
  Signalez toute erreur au premier essai.
