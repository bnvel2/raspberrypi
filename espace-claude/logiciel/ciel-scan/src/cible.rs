//! Analyse de la cible : adresse seule, CIDR, plage ou liste séparée par des virgules.
//! Contient aussi le garde-fou de périmètre (réseaux privés uniquement par défaut).

use std::net::Ipv4Addr;

/// Nombre maximal d'adresses par balayage (équivalent d'un /16).
pub const MAX_HOTES: u64 = 65_536;

fn analyser_ip(s: &str) -> Result<Ipv4Addr, String> {
    s.trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("adresse IPv4 invalide : « {} »", s.trim()))
}

fn depuis_cidr(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (ip_s, bits_s) = s.split_once('/').ok_or("CIDR invalide")?;
    let ip = analyser_ip(ip_s)?;
    let bits: u32 = bits_s
        .trim()
        .parse()
        .map_err(|_| format!("masque invalide : « {} »", bits_s.trim()))?;
    if bits > 32 {
        return Err(format!("masque invalide : /{bits}"));
    }
    let taille: u64 = 1u64 << (32 - bits);
    if taille > MAX_HOTES {
        return Err(format!(
            "plage trop grande ({taille} adresses, maximum {MAX_HOTES})"
        ));
    }
    let masque: u32 = u32::MAX << (32 - bits);
    let reseau = u32::from(ip) & masque;
    // Pour /31 et /32 on garde toutes les adresses ; sinon on retire réseau et diffusion.
    let (debut, fin) = if bits >= 31 {
        (reseau as u64, reseau as u64 + taille - 1)
    } else {
        (reseau as u64 + 1, reseau as u64 + taille - 2)
    };
    Ok((debut..=fin).map(|n| Ipv4Addr::from(n as u32)).collect())
}

fn depuis_plage(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (a, b) = s.split_once('-').ok_or("plage invalide")?;
    let debut = analyser_ip(a)?;
    // La fin peut être une adresse complète ou seulement le dernier octet.
    let fin = match b.trim().parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => {
            let dernier: u8 = b
                .trim()
                .parse()
                .map_err(|_| format!("fin de plage invalide : « {} »", b.trim()))?;
            let o = debut.octets();
            Ipv4Addr::new(o[0], o[1], o[2], dernier)
        }
    };
    let (d, f) = (u32::from(debut), u32::from(fin));
    if f < d {
        return Err("la fin de la plage précède son début".into());
    }
    let nb = (f - d) as u64 + 1;
    if nb > MAX_HOTES {
        return Err(format!(
            "plage trop grande ({nb} adresses, maximum {MAX_HOTES})"
        ));
    }
    Ok((d..=f).map(Ipv4Addr::from).collect())
}

/// Transforme une description de cible en liste triée d'adresses, sans doublon.
pub fn analyser_cibles(spec: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut sortie: Vec<Ipv4Addr> = Vec::new();
    for morceau in spec.split(',').map(str::trim).filter(|m| !m.is_empty()) {
        let mut v = if morceau.contains('/') {
            depuis_cidr(morceau)?
        } else if morceau.contains('-') {
            depuis_plage(morceau)?
        } else {
            vec![analyser_ip(morceau)?]
        };
        sortie.append(&mut v);
        if sortie.len() as u64 > MAX_HOTES {
            return Err(format!("trop d'adresses (maximum {MAX_HOTES})"));
        }
    }
    if sortie.is_empty() {
        return Err("aucune cible indiquée".into());
    }
    sortie.sort();
    sortie.dedup();
    Ok(sortie)
}

pub fn est_prive(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// Refuse les adresses publiques sauf demande explicite de l'utilisateur.
pub fn verifier_perimetre(ips: &[Ipv4Addr], autoriser_public: bool) -> Result<(), String> {
    if autoriser_public {
        return Ok(());
    }
    match ips.iter().find(|ip| !est_prive(**ip)) {
        Some(ip) => Err(format!(
            "{ip} n'est pas une adresse privée. Par défaut, seuls les réseaux privés \
             (10/8, 172.16/12, 192.168/16, boucle locale, lien local) sont analysés. \
             Si vous avez l'autorisation écrite du propriétaire du réseau, \
             ajoutez --autoriser-public."
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresse_seule() {
        assert_eq!(
            analyser_cibles("192.168.1.10").unwrap(),
            vec![Ipv4Addr::new(192, 168, 1, 10)]
        );
    }

    #[test]
    fn cidr_24_exclut_reseau_et_diffusion() {
        let v = analyser_cibles("192.168.1.0/24").unwrap();
        assert_eq!(v.len(), 254);
        assert_eq!(v[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(v[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn cidr_32_et_31() {
        assert_eq!(analyser_cibles("10.0.0.5/32").unwrap().len(), 1);
        assert_eq!(analyser_cibles("10.0.0.4/31").unwrap().len(), 2);
    }

    #[test]
    fn plage_complete_et_courte() {
        assert_eq!(analyser_cibles("192.168.1.10-192.168.1.20").unwrap().len(), 11);
        assert_eq!(analyser_cibles("192.168.1.10-20").unwrap().len(), 11);
    }

    #[test]
    fn liste_dedoublonnee() {
        let v = analyser_cibles("10.0.0.1, 10.0.0.1, 10.0.0.2").unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn erreurs() {
        assert!(analyser_cibles("10.0.0.0/8").is_err()); // trop grand
        assert!(analyser_cibles("10.0.0.0/33").is_err());
        assert!(analyser_cibles("pas-une-ip").is_err());
        assert!(analyser_cibles("10.0.0.20-10.0.0.10").is_err());
        assert!(analyser_cibles("").is_err());
    }

    #[test]
    fn perimetre() {
        let privees = analyser_cibles("192.168.1.1,10.1.2.3,127.0.0.1").unwrap();
        assert!(verifier_perimetre(&privees, false).is_ok());
        let publique = analyser_cibles("8.8.8.8").unwrap();
        assert!(verifier_perimetre(&publique, false).is_err());
        assert!(verifier_perimetre(&publique, true).is_ok());
    }
}
