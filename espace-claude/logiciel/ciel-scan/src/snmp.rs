//! Client SNMP v2c minimal (requête GET), écrit à la main d'après le codage BER (ASN.1).
//!
//! Il lit deux objets standard de la MIB-II : sysDescr (1.3.6.1.2.1.1.1.0)
//! et sysName (1.3.6.1.2.1.1.5.0). La communauté est fournie par l'utilisateur
//! (« public » par défaut, valeur de lecture courante) : aucun essai de mots de
//! passe n'est effectué.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OID_SYS_DESCR: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 1, 0];
const OID_SYS_NAME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 5, 0];

#[derive(Debug, Default, Clone)]
pub struct InfoSnmp {
    pub nom: Option<String>,
    pub description: Option<String>,
}

// ---------- Encodage BER ----------

fn ajouter_longueur(v: &mut Vec<u8>, n: usize) {
    if n < 128 {
        v.push(n as u8);
    } else if n < 256 {
        v.push(0x81);
        v.push(n as u8);
    } else {
        v.push(0x82);
        v.push((n >> 8) as u8);
        v.push((n & 0xFF) as u8);
    }
}

fn tlv(etiquette: u8, contenu: &[u8]) -> Vec<u8> {
    let mut v = vec![etiquette];
    ajouter_longueur(&mut v, contenu.len());
    v.extend_from_slice(contenu);
    v
}

/// Entier ASN.1 sur le nombre minimal d'octets (complément à deux).
fn entier(n: i32) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut debut = 0;
    while debut < 3
        && ((b[debut] == 0x00 && b[debut + 1] & 0x80 == 0)
            || (b[debut] == 0xFF && b[debut + 1] & 0x80 != 0))
    {
        debut += 1;
    }
    tlv(0x02, &b[debut..])
}

/// Contenu (sans en-tête) d'un identifiant d'objet : les deux premiers arcs
/// sont fusionnés (40*a+b), les suivants codés en base 128.
fn oid_contenu(arcs: &[u32]) -> Vec<u8> {
    let mut c = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut groupes = vec![(arc & 0x7F) as u8];
        let mut reste = arc >> 7;
        while reste > 0 {
            groupes.push((reste & 0x7F) as u8 | 0x80);
            reste >>= 7;
        }
        groupes.reverse();
        c.extend(groupes);
    }
    c
}

/// Construit un message SNMP v2c GetRequest pour la liste d'OID donnée.
pub fn construire_get(communaute: &str, id_requete: i32, oids: &[&[u32]]) -> Vec<u8> {
    let mut varbinds = Vec::new();
    for oid in oids {
        let mut paire = tlv(0x06, &oid_contenu(oid));
        paire.extend(tlv(0x05, &[])); // valeur NULL
        varbinds.extend(tlv(0x30, &paire));
    }
    let mut pdu = entier(id_requete);
    pdu.extend(entier(0)); // error-status
    pdu.extend(entier(0)); // error-index
    pdu.extend(tlv(0x30, &varbinds));

    let mut message = entier(1); // version : 1 = SNMP v2c
    message.extend(tlv(0x04, communaute.as_bytes()));
    message.extend(tlv(0xA0, &pdu)); // GetRequest-PDU
    tlv(0x30, &message)
}

// ---------- Décodage BER ----------

/// Lit un élément TLV : retourne (étiquette, contenu, reste).
fn lire_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let etiquette = buf[0];
    let (longueur, decalage) = if buf[1] < 0x80 {
        (buf[1] as usize, 2)
    } else {
        let n = (buf[1] & 0x7F) as usize;
        if n == 0 || n > 2 || buf.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | buf[2 + i] as usize;
        }
        (l, 2 + n)
    };
    if buf.len() < decalage + longueur {
        return None;
    }
    Some((
        etiquette,
        &buf[decalage..decalage + longueur],
        &buf[decalage + longueur..],
    ))
}

/// Décode une réponse GetResponse : liste de (contenu de l'OID, valeur texte si OCTET STRING).
pub fn lire_reponse(buf: &[u8]) -> Option<Vec<(Vec<u8>, Option<String>)>> {
    let (t, message, _) = lire_tlv(buf)?;
    if t != 0x30 {
        return None;
    }
    let (_, _version, reste) = lire_tlv(message)?;
    let (_, _communaute, reste) = lire_tlv(reste)?;
    let (t, pdu, _) = lire_tlv(reste)?;
    if t != 0xA2 {
        return None; // pas un GetResponse
    }
    let (_, _id, reste) = lire_tlv(pdu)?;
    let (_, erreur, reste) = lire_tlv(reste)?;
    if erreur.iter().any(|&b| b != 0) {
        return None;
    }
    let (_, _index, reste) = lire_tlv(reste)?;
    let (t, liste, _) = lire_tlv(reste)?;
    if t != 0x30 {
        return None;
    }
    let mut sortie = Vec::new();
    let mut courant: &[u8] = liste;
    while !courant.is_empty() {
        let (_, paire, suite) = lire_tlv(courant)?;
        courant = suite;
        let (_, oid, reste) = lire_tlv(paire)?;
        let (type_valeur, valeur, _) = lire_tlv(reste)?;
        let texte = if type_valeur == 0x04 {
            Some(String::from_utf8_lossy(valeur).trim().to_string())
        } else {
            None
        };
        sortie.push((oid.to_vec(), texte));
    }
    Some(sortie)
}

// ---------- Requête réseau ----------

pub fn interroger(ip: Ipv4Addr, communaute: &str, delai: Duration) -> Option<InfoSnmp> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(delai)).ok()?;
    socket.connect((ip, 161)).ok()?;

    let id = (SystemTime::now().duration_since(UNIX_EPOCH).ok()?.subsec_nanos() & 0x7FFF_FFFF) as i32;
    let requete = construire_get(communaute, id, &[&OID_SYS_DESCR, &OID_SYS_NAME]);
    socket.send(&requete).ok()?;

    let mut tampon = [0u8; 1500];
    let n = socket.recv(&mut tampon).ok()?;
    let valeurs = lire_reponse(&tampon[..n])?;

    let oid_descr = oid_contenu(&OID_SYS_DESCR);
    let oid_nom = oid_contenu(&OID_SYS_NAME);
    let mut info = InfoSnmp::default();
    for (oid, texte) in valeurs {
        if oid == oid_descr {
            info.description = texte.filter(|t| !t.is_empty());
        } else if oid == oid_nom {
            info.nom = texte.filter(|t| !t.is_empty());
        }
    }
    if info.nom.is_none() && info.description.is_none() {
        None
    } else {
        Some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requête construite à la main, octet par octet, d'après la norme (voir README).
    #[test]
    fn requete_sysdescr_communaute_public() {
        let attendu: Vec<u8> = vec![
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xA0,
            0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C,
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ];
        assert_eq!(construire_get("public", 1, &[&OID_SYS_DESCR]), attendu);
    }

    #[test]
    fn entiers_minimaux() {
        assert_eq!(entier(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(entier(127), vec![0x02, 0x01, 0x7F]);
        assert_eq!(entier(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(entier(-1), vec![0x02, 0x01, 0xFF]);
        assert_eq!(entier(256), vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn oid_avec_arc_superieur_a_127() {
        // 1.3.6.1.4.1.311 (Microsoft) : 311 = 0x137 -> 0x82 0x37
        assert_eq!(
            oid_contenu(&[1, 3, 6, 1, 4, 1, 311]),
            vec![0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37]
        );
    }

    #[test]
    fn longueur_en_forme_longue() {
        let contenu = vec![0u8; 200];
        let t = tlv(0x04, &contenu);
        assert_eq!(&t[..3], &[0x04, 0x81, 200]);
        let contenu = vec![0u8; 300];
        let t = tlv(0x04, &contenu);
        assert_eq!(&t[..4], &[0x04, 0x82, 0x01, 0x2C]);
    }

    /// Réponse écrite à la main, octet par octet : un seul objet, valeur « sw1 ».
    /// Longueurs : OID 2+7=9, valeur 2+3=5, paire 14 (0x0E), liste 2+14=16 (0x10),
    /// PDU 9+2+16=27 (0x1B), message 3+8+2+27=40 (0x28).
    #[test]
    fn lecture_reponse() {
        let reponse: Vec<u8> = vec![
            0x30, 0x28, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xA2,
            0x1B, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x10, 0x30, 0x0E,
            0x06, 0x07, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x04, 0x03, b's', b'w', b'1',
        ];
        assert_eq!(reponse.len(), 42);
        let v = lire_reponse(&reponse).expect("la trame doit être lisible");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, vec![0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05]);
        assert_eq!(v[0].1.as_deref(), Some("sw1"));
    }

    #[test]
    fn reponse_invalide_ou_erreur() {
        assert!(lire_reponse(&[]).is_none());
        assert!(lire_reponse(&[0x30, 0x02, 0x02, 0x01]).is_none());
        // Un GetRequest (0xA0) n'est pas une réponse.
        let requete = construire_get("public", 1, &[&OID_SYS_NAME]);
        assert!(lire_reponse(&requete).is_none());
    }
}
