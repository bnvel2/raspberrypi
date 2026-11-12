//! Scan de ports TCP par connexion complète (méthode « connect »).

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// Ports courants d'un réseau d'entreprise ou d'établissement.
pub const PORTS_PAR_DEFAUT: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080,
];

/// Accepte « defaut », ou une liste du type « 22,80,8000-8010 ».
pub fn analyser_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("defaut") || spec.eq_ignore_ascii_case("défaut") {
        return Ok(PORTS_PAR_DEFAUT.to_vec());
    }
    let mut sortie: Vec<u16> = Vec::new();
    for morceau in spec.split(',').map(str::trim).filter(|m| !m.is_empty()) {
        if let Some((a, b)) = morceau.split_once('-') {
            let a: u16 = a.trim().parse().map_err(|_| format!("port invalide : « {morceau} »"))?;
            let b: u16 = b.trim().parse().map_err(|_| format!("port invalide : « {morceau} »"))?;
            if a == 0 || b < a {
                return Err(format!("plage de ports invalide : « {morceau} »"));
            }
            sortie.extend(a..=b);
        } else {
            let p: u16 = morceau
                .parse()
                .map_err(|_| format!("port invalide : « {morceau} »"))?;
            if p == 0 {
                return Err("le port 0 n'existe pas".into());
            }
            sortie.push(p);
        }
    }
    if sortie.is_empty() {
        return Err("aucun port indiqué".into());
    }
    sortie.sort_unstable();
    sortie.dedup();
    Ok(sortie)
}

/// Retourne les ports qui acceptent une connexion TCP.
pub fn ports_ouverts(ip: Ipv4Addr, ports: &[u16], delai: Duration) -> Vec<u16> {
    ports
        .iter()
        .copied()
        .filter(|&p| TcpStream::connect_timeout(&SocketAddr::new(ip.into(), p), delai).is_ok())
        .collect()
}

/// Nom usuel du service associé à un port (indicatif : seul le port est testé).
pub fn nom_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "rpc",
        139 => "netbios",
        143 => "imap",
        161 => "snmp",
        443 => "https",
        445 => "smb",
        3389 => "rdp",
        8080 => "http-alt",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn analyse_liste_et_plage() {
        assert_eq!(analyser_ports("80, 22,8000-8002").unwrap(), vec![22, 80, 8000, 8001, 8002]);
        assert_eq!(analyser_ports("defaut").unwrap(), PORTS_PAR_DEFAUT.to_vec());
    }

    #[test]
    fn analyse_erreurs() {
        assert!(analyser_ports("abc").is_err());
        assert!(analyser_ports("0").is_err());
        assert!(analyser_ports("90-80").is_err());
        assert!(analyser_ports("70000").is_err());
    }

    #[test]
    fn detecte_un_port_ouvert_et_un_port_ferme() {
        let ecouteur = TcpListener::bind("127.0.0.1:0").unwrap();
        let ouvert = ecouteur.local_addr().unwrap().port();
        // Un port fermé : on lie puis on libère.
        let ferme = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let res = ports_ouverts(
            Ipv4Addr::LOCALHOST,
            &[ouvert, ferme],
            Duration::from_millis(300),
        );
        assert_eq!(res, vec![ouvert]);
    }
}
