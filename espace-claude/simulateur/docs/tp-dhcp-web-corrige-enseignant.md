# TP Packet Tracer : DHCP et serveur Web distant

**Corrigé enseignant** – Ne pas distribuer aux élèves

## 1. Rappel de la maquette

| Équipement | Interface | Adresse IP | Masque | Passerelle |
| --- | --- | --- | --- | --- |
| R1 | G0/0 (LAN A) | 192.168.10.1 | 255.255.255.0 | – |
| R1 | G0/1 (WAN) | 10.0.0.1 | 255.255.255.252 | – |
| R2 | G0/1 (WAN) | 10.0.0.2 | 255.255.255.252 | – |
| R2 | G0/0 (LAN B) | 172.16.0.1 | 255.255.255.0 | – |
| Serveur DHCP | NIC | 192.168.10.2 | 255.255.255.0 | 192.168.10.1 |
| Serveur Web | NIC | 172.16.0.10 | 255.255.255.0 | 172.16.0.1 |
| Serveur DNS | NIC | 172.16.0.11 | 255.255.255.0 | 172.16.0.1 |
| PC0, PC1, Laptop | NIC | DHCP | DHCP | DHCP |

## 2. Partie A – Montage

**Câblage attendu :**

- PC0, PC1, Laptop et Serveur DHCP vers Switch0 (câbles droits, ports FastEthernet).
- Switch0 vers R1 G0/0 (câble droit).
- R1 G0/1 vers R2 G0/1 (câble croisé).
- R2 G0/0 vers Switch1 (câble droit).
- Switch1 vers Serveur Web et Serveur DNS (câbles droits).

**Question A1 :** on utilise un câble croisé car on relie deux équipements de même nature (routeur vers routeur) : l'émission de l'un doit arriver sur la réception de l'autre. Précision : sur du matériel récent, l'auto-MDIX gère cela, mais dans Packet Tracer le câble croisé est le choix attendu et le plus sûr. Les autres liens sont tous droits entre équipements de nature différente (poste vers switch, switch vers routeur).

## 3. Partie B – Configuration des routeurs

**R1**

```
enable
configure terminal
hostname R1
interface g0/0
 ip address 192.168.10.1 255.255.255.0
 no shutdown
interface g0/1
 ip address 10.0.0.1 255.255.255.252
 no shutdown
exit
ip route 172.16.0.0 255.255.255.0 10.0.0.2
end
write memory
```

**R2**

```
enable
configure terminal
hostname R2
interface g0/0
 ip address 172.16.0.1 255.255.255.0
 no shutdown
interface g0/1
 ip address 10.0.0.2 255.255.255.252
 no shutdown
exit
ip route 192.168.10.0 255.255.255.0 10.0.0.1
end
write memory
```

**Question B1 :**

- R1 : `ip route 172.16.0.0 255.255.255.0 10.0.0.2`
- R2 : `ip route 192.168.10.0 255.255.255.0 10.0.0.1`

Chaque route indique : « pour joindre le réseau de destination, envoyer les paquets à l'adresse du routeur voisin (prochain saut) ».

**Question B2 :** le masque /30 (255.255.255.252) laisse 2 bits pour la partie hôte, soit 4 adresses au total, dont l'adresse réseau et l'adresse de diffusion. Il reste **2 hôtes** utilisables, ce qui est exactement ce qu'il faut pour une liaison point à point entre deux routeurs.

**Erreurs fréquentes :** oubli de `no shutdown` (interface administrativement down), inversion du masque et de l'adresse de prochain saut dans la route, oubli de la route sur l'un des deux routeurs.

## 4. Partie C – Configuration des serveurs

**Serveur DHCP** (*Services > DHCP*, service **On**) :

| Paramètre | Valeur |
| --- | --- |
| Pool Name | serverPool |
| Default Gateway | 192.168.10.1 |
| DNS Server | 172.16.0.11 |
| Start IP Address | 192.168.10.10 |
| Subnet Mask | 255.255.255.0 |
| Maximum Number of Users | 50 |

Cliquer sur **Save** (si le pool `serverPool` existe déjà, le modifier plutôt que d'en créer un second : il ne peut pas être renommé ni supprimé dans Packet Tracer). Sans validation, le pool n'est pas pris en compte : c'est l'erreur la plus fréquente.

**Serveur Web** (*Services > HTTP*) : HTTP **On**, éditer `index.html` avec un message contenant le nom de l'élève, puis **Save**.

**Serveur DNS** (*Services > DNS*) : DNS **On**, enregistrement `www.monsite.local`, type **A Record**, adresse `172.16.0.10`, puis **Add**.

**Question C1 :** un serveur doit être joignable à une adresse fixe et connue. Les clients, le DNS et la configuration du DHCP s'appuient sur cette adresse. Avec une adresse dynamique, elle pourrait changer et rendre le service injoignable. De plus, le serveur DHCP ne peut pas obtenir son adresse de lui-même : c'est lui qui distribue les adresses.

## 5. Partie D – Clients

Résultat attendu (l'ordre d'attribution peut varier) :

| Poste | Adresse IP | Masque | Passerelle | DNS |
| --- | --- | --- | --- | --- |
| PC0 | 192.168.10.10 | 255.255.255.0 | 192.168.10.1 | 172.16.0.11 |
| PC1 | 192.168.10.11 | 255.255.255.0 | 192.168.10.1 | 172.16.0.11 |
| Laptop | 192.168.10.12 | 255.255.255.0 | 192.168.10.1 | 172.16.0.11 |

**Question D1 :** non, les adresses IP sont différentes : le serveur DHCP attribue une adresse libre différente à chaque client dans la plage du pool, et deux machines ne peuvent pas avoir la même adresse sur un réseau. Le masque, la passerelle et le DNS sont en revanche identiques car ils sont communs au pool.

**Si un poste affiche 169.254.x.x :** il n'a pas reçu d'offre DHCP (adressage APIPA). Causes possibles : service DHCP à Off, pool non sauvegardé, liens encore orange, serveur DHCP avec une mauvaise passerelle ou un mauvais masque.

## 6. Partie E – Tests et validation

| Test | Résultat attendu |
| --- | --- |
| `ping` vers 192.168.10.1 | Réussi |
| `ping` vers 10.0.0.2 | Réussi |
| `ping` vers 172.16.0.10 | Réussi (le premier paquet peut échouer le temps de la résolution ARP) |
| Navigateur `http://172.16.0.10` | Page personnalisée affichée |
| Navigateur `http://www.monsite.local` | Page personnalisée affichée |

**Ligne attendue dans `show ip route` sur R1 :**

```
S    172.16.0.0/24 [1/0] via 10.0.0.2
```

Les réseaux connectés apparaissent avec le code `C` (192.168.10.0/24 et 10.0.0.0/30) et les adresses locales avec le code `L`.

`show ip interface brief` : les interfaces G0/0 et G0/1 doivent être « up / up ».

## 7. Partie F – Observation DORA

| Étape | Message | IP source | IP destination |
| --- | --- | --- | --- |
| 1 | DHCP Discover | 0.0.0.0 | 255.255.255.255 |
| 2 | DHCP Offer | 192.168.10.2 | 255.255.255.255 (ou adresse proposée) |
| 3 | DHCP Request | 0.0.0.0 | 255.255.255.255 |
| 4 | DHCP Acknowledge | 192.168.10.2 | 255.255.255.255 (ou adresse attribuée) |

Les adresses de destination des messages Offer et Acknowledge peuvent différer selon la version de Packet Tracer : accepter les deux réponses si l'élève justifie ce qu'il observe.

**Question F1 :** au moment du Discover, le client n'a aucune adresse IP et ne connaît ni le serveur DHCP ni sa propre passerelle. Il ne peut donc pas contacter un destinataire précis : il diffuse sa demande à tout le réseau local (255.255.255.255), et seul un serveur DHCP y répondra. Cette diffusion ne franchit pas le routeur, d'où le serveur DHCP placé dans le même LAN (ou l'usage d'un relais DHCP).

## 8. Partie G – Pannes suggérées pour le dépannage

| Panne introduite | Symptôme | Diagnostic | Correction |
| --- | --- | --- | --- |
| Passerelle erronée dans le pool DHCP | Les clients reçoivent une IP mais n'atteignent pas le serveur Web | `ipconfig` : mauvaise passerelle | Corriger le pool, puis renouveler le bail |
| Route statique supprimée sur R2 | Ping vers le Web en échec (« Request timed out ») | `show ip route` sur R2 : pas de route vers 192.168.10.0 | Rétablir la route |
| `shutdown` sur R1 G0/1 | Aucun accès au réseau distant | `show ip interface brief` : interface administratively down | `no shutdown` |
| Service HTTP à Off | Ping réussi mais navigateur en échec | Services du serveur Web | Activer HTTP |
| Service DHCP à Off | Clients en 169.254.x.x | Services du serveur DHCP | Activer DHCP |
| Mauvais masque sur un lien WAN | Ping WAN en échec | `show ip interface brief` et configuration | Corriger le masque |

**Démarche méthodique attendue (de proche en proche) :** vérifier le poste (`ipconfig`), puis la passerelle, puis le routeur voisin, puis le réseau distant, puis le service (HTTP, DNS).

## 9. Corrigé des questions de synthèse

1. **Route statique supprimée sur R2 :** le paquet aller atteint le serveur Web (R1 connaît la route vers 172.16.0.0/24), mais R2 ne sait pas où renvoyer la réponse destinée à 192.168.10.x : elle est perdue. Le ping échoue donc, car il nécessite un aller-retour. Le routage doit toujours être configuré dans les deux sens.
2. **Décision du routeur :** il compare l'adresse de destination (172.16.0.10) aux réseaux de sa table de routage, retient la route correspondante la plus spécifique (plus long préfixe), et envoie le paquet vers le prochain saut (10.0.0.2) par l'interface associée (G0/1).
3. **Plage commençant à .10 :** on réserve les adresses .1 à .9 aux équipements à adresse fixe (routeur en .1, serveur DHCP en .2, et de la marge pour imprimantes ou autres serveurs), afin d'éviter qu'une adresse distribuée entre en conflit avec une adresse statique.
4. **Intérêt du DNS :** on retient un nom plutôt qu'une adresse numérique, et si l'adresse du serveur change, seul l'enregistrement DNS est modifié : les utilisateurs n'ont rien à changer.

## 10. Corrigé du bonus

**Relais DHCP** (serveur DHCP dans le LAN B, par exemple en 172.16.0.12) :

```
R1(config)# interface g0/0
R1(config-if)# ip helper-address 172.16.0.12
```

Le pool doit alors cibler le réseau 192.168.10.0/24 avec la passerelle 192.168.10.1 sur le serveur DHCP distant. R2 doit connaître la route vers 192.168.10.0/24 (déjà présente). Le routeur transforme la diffusion du client en message direct (unicast) vers le serveur DHCP.

**DHCP sur le routeur R1 :**

```
ip dhcp excluded-address 192.168.10.1 192.168.10.9
ip dhcp pool LAN1
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 172.16.0.11
```

Vérification : `show ip dhcp binding` et `show ip dhcp pool`.

## 11. Barème de correction (sur 20)

| Compétence | Points | Indications de notation |
| --- | --- | --- |
| Montage | 2 | 0,5 par erreur de câblage ou de nom, jusqu'à 0 |
| Routeurs : interfaces | 2 | 1 par routeur (adresses et `no shutdown`) |
| Routeurs : routes statiques | 2 | 1 par route correcte |
| Serveur DHCP | 3 | 1 adresse statique, 1 pool complet, 1 pool validé et fonctionnel |
| Serveur Web / DNS | 2 | 1 page personnalisée, 1 enregistrement DNS |
| Clients | 1 | Les 3 postes en DHCP avec adresses valides |
| Validation | 3 | 1 ping, 1 accès par IP, 1 accès par nom |
| Observation DORA | 2 | 1,5 pour le tableau, 0,5 pour F1 |
| Questions | 2 | Réponses justes et argumentées |
| Dépannage | 1 | Démarche méthodique, même si la panne n'est pas résolue |
| **Total** | **20** | Bonus jusqu'à +2 |

## 12. Conseils de mise en œuvre

- Prévoir 2 heures ; la partie F et le bonus peuvent être donnés à part pour une séance courte.
- Fournir aux élèves en difficulté un fichier `.pkt` pré-câblé (sans configuration) afin qu'ils se concentrent sur l'adressage et le routage.
- Pour l'évaluation, demander de sauvegarder le fichier `.pkt` nommé `NOM_Prenom_TP_DHCP.pkt` et de le rendre sur l'espace de dépôt.
- Packet Tracer peut afficher des liens orange pendant quelques secondes : inviter les élèves à attendre ou à utiliser le bouton d'avance rapide (*Fast Forward Time*) avant de conclure à une panne.
