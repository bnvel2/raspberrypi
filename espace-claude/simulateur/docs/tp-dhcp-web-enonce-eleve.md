# TP Packet Tracer : DHCP et serveur Web distant

**Énoncé élève** – Durée prévue : 2 heures – Logiciel : Cisco Packet Tracer

Nom : ____________  Prénom : ____________  Classe : ______  Date : ________

## 1. Contexte

Une petite entreprise possède deux sites reliés par une liaison point à point entre deux routeurs. Sur le **site A**, les postes de travail doivent recevoir automatiquement leur configuration IP grâce à un **serveur DHCP**. Sur le **site B** se trouve un **serveur Web** (et un serveur DNS) que les postes du site A doivent pouvoir consulter.

Votre mission : construire la maquette, la configurer, puis prouver qu'elle fonctionne.

## 2. Objectifs

- Configurer un serveur DHCP (pool d'adresses, passerelle, DNS).
- Configurer deux routeurs et le routage statique entre deux réseaux.
- Configurer un serveur Web et un serveur DNS.
- Tester et diagnostiquer la connectivité avec `ping`, `ipconfig` et le navigateur.
- Observer un échange DHCP en mode Simulation.

## 3. Matériel à utiliser

- 2 routeurs Cisco 2911 (ou 1941)
- 2 commutateurs 2960
- 3 postes clients (PC0, PC1 et un Laptop)
- 3 serveurs : DHCP, Web, DNS
- Câbles droits (postes, serveurs et commutateurs vers routeurs) et un câble croisé entre les deux routeurs

## 4. Schéma logique

```
[PC0]──┐
[PC1]──┼─[Switch0]──[R1]══(10.0.0.0/30)══[R2]──[Switch1]──[Serveur Web]
[Laptop]┘     │                                             [Serveur DNS]
        [Serveur DHCP]
```

## 5. Plan d'adressage

| Équipement | Interface | Adresse IP | Masque | Passerelle |
| --- | --- | --- | --- | --- |
| R1 | G0/0 (LAN A) | 192.168.10.1 | 255.255.255.0 | – |
| R1 | G0/1 (WAN) | 10.0.0.1 | 255.255.255.252 | – |
| R2 | G0/1 (WAN) | 10.0.0.2 | 255.255.255.252 | – |
| R2 | G0/0 (LAN B) | 172.16.0.1 | 255.255.255.0 | – |
| Serveur DHCP | NIC | 192.168.10.2 | 255.255.255.0 | 192.168.10.1 |
| Serveur Web | NIC | 172.16.0.10 | 255.255.255.0 | 172.16.0.1 |
| Serveur DNS | NIC | 172.16.0.11 | 255.255.255.0 | 172.16.0.1 |
| PC0, PC1, Laptop | NIC | **DHCP** | **DHCP** | **DHCP** |

## 6. Travail demandé

### Partie A – Montage (20 min)

1. Placez et nommez tous les équipements selon le schéma (R1, R2, Switch0, Switch1, DHCP, WEB, DNS, PC0, PC1, Laptop).
2. Câblez la maquette. Vérifiez que tous les liens passent au vert (patientez quelques secondes).
3. **Question A1** : pourquoi utilise-t-on un câble croisé entre les deux routeurs ?

   Réponse : ____________________________________________

### Partie B – Configuration des routeurs (25 min)

1. Sur chaque routeur, donnez un nom (`hostname`), configurez les deux interfaces selon le plan d'adressage et activez-les.
2. Ajoutez sur chaque routeur la **route statique** permettant d'atteindre le réseau de l'autre site.
3. Sauvegardez la configuration.
4. Depuis R1, testez `ping 10.0.0.2`.
5. **Question B1** : écrivez la commande de route statique saisie sur R1 et sur R2.

   R1 : ____________________________________________

   R2 : ____________________________________________
6. **Question B2** : que signifie le masque /30 ? Combien d'hôtes peut-on adresser ?

   Réponse : ____________________________________________

### Partie C – Configuration des serveurs (30 min)

1. **Serveur DHCP** : configurez son adresse IP en statique (*Desktop > IP Configuration*). Dans *Services > DHCP*, activez le service et modifiez le pool par défaut (non renommable) `serverPool` :
   - passerelle par défaut : adresse de R1 côté LAN A
   - serveur DNS : adresse du serveur DNS
   - première adresse : 192.168.10.10
   - masque : 255.255.255.0
   - nombre maximum d'utilisateurs : 50
   - n'oubliez pas de valider avec **Save** ou **Add**.
2. **Serveur Web** : configurez son adresse IP en statique, activez le service HTTP et personnalisez la page `index.html` (mettez votre nom dedans).
3. **Serveur DNS** : configurez son adresse IP en statique, activez le service DNS et ajoutez un enregistrement de type A : `www.monsite.local` vers l'adresse du serveur Web.
4. **Question C1** : pourquoi les serveurs ont-ils une adresse statique et non une adresse DHCP ?

   Réponse : ____________________________________________

### Partie D – Configuration des clients (10 min)

1. Sur chaque poste client : *Desktop > IP Configuration > DHCP*.
2. Relevez la configuration obtenue :

| Poste | Adresse IP | Masque | Passerelle | DNS |
| --- | --- | --- | --- | --- |
| PC0 |  |  |  |  |
| PC1 |  |  |  |  |
| Laptop |  |  |  |  |

3. **Question D1** : les trois adresses sont-elles identiques ? Pourquoi ?

   Réponse : ____________________________________________

### Partie E – Tests et validation (20 min)

Depuis PC0, réalisez les tests suivants et notez le résultat (réussi / échec) :

| Test | Résultat |
| --- | --- |
| `ping` vers la passerelle (R1) |  |
| `ping` vers 10.0.0.2 (R2) |  |
| `ping` vers le serveur Web par son adresse IP |  |
| Navigateur : `http://` suivi de l'adresse IP du serveur Web |  |
| Navigateur : `http://www.monsite.local` |  |

Sur R1, exécutez `show ip route` et `show ip interface brief`. Recopiez la ligne correspondant à la route vers le LAN B :

---

**Faites valider votre maquette par l'enseignant** une fois les tests réussis. Visa : ____________

### Partie F – Observation en mode Simulation (15 min)

1. Passez en mode **Simulation**, filtrez sur les protocoles **DHCP**, puis **HTTP** (et DNS si configuré).
2. Sur un poste, relâchez puis redemandez son adresse (*IP Configuration* : repassez en Static puis en DHCP).
3. Observez les paquets et complétez :

| Étape DHCP | Nom du message | Adresse IP source | Adresse IP destination |
| --- | --- | --- | --- |
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |

4. **Question F1** : pourquoi le premier message est-il envoyé en diffusion (broadcast) ?

   Réponse : ____________________________________________

### Partie G – Dépannage (10 min)

L'enseignant introduit une panne dans votre maquette (ou vous en provoquez une volontairement). Décrivez la démarche suivie :

- Symptôme observé : ____________________________________________
- Tests effectués : ____________________________________________
- Cause trouvée : ____________________________________________
- Correction apportée : ____________________________________________

## 7. Questions de synthèse

1. Que se passe-t-il si on supprime la route statique sur R2 ? Le ping depuis PC0 vers le serveur Web aboutit-il ? Justifiez.
2. Comment un routeur décide-t-il de la direction d'un paquet destiné à 172.16.0.10 ?
3. Pourquoi la plage DHCP commence-t-elle à 192.168.10.10 ?
4. Quel est l'intérêt du DNS par rapport à l'utilisation directe de l'adresse IP ?

## 8. Pour aller plus loin (bonus)

- Déplacez le serveur DHCP dans le LAN B et faites fonctionner la distribution d'adresses dans le LAN A grâce à la commande `ip helper-address` sur R1.
- Remplacez le serveur DHCP par un service DHCP configuré directement sur R1 (`ip dhcp pool`, `ip dhcp excluded-address`).

## 9. Grille d'évaluation (sur 20)

| Compétence | Critère | Points | Obtenu |
| --- | --- | --- | --- |
| Montage | Équipements corrects, nommés et câblés | 2 |  |
| Routeurs | Interfaces configurées et actives | 2 |  |
| Routeurs | Routes statiques correctes | 2 |  |
| Serveur DHCP | Adresse statique et pool correctement renseigné | 3 |  |
| Serveur Web / DNS | Services actifs, page personnalisée, enregistrement DNS | 2 |  |
| Clients | Adresses obtenues en DHCP | 1 |  |
| Validation | Ping et accès Web réussis (IP et nom) | 3 |  |
| Observation | Tableau DORA et question F1 | 2 |  |
| Questions | Réponses justes et argumentées (A1, B1, B2, C1, D1, synthèse) | 2 |  |
| Dépannage | Démarche méthodique | 1 |  |
| **Total** |  | **20** |  |

Bonus : jusqu'à +2 points pour la partie « Pour aller plus loin ».

**Remarques de l'enseignant :**
