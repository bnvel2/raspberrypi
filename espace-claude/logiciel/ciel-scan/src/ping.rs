//! Test de présence par ping.
//!
//! On appelle la commande `ping` du système : elle fonctionne sans droits
//! administrateur, contrairement à l'ouverture d'un socket ICMP brut.
//! La réponse est reconnue par la présence de « ttl= » (insensible à la casse
//! et identique quelle que soit la langue du système).

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

pub fn repond_au_ping(ip: Ipv4Addr, delai_ms: u64) -> bool {
    let ip_texte = ip.to_string();
    let mut cmd = Command::new("ping");

    #[cfg(windows)]
    cmd.args(["-n", "1", "-w", &delai_ms.to_string(), &ip_texte]);

    #[cfg(not(windows))]
    {
        // Sous Linux/macOS le délai de `-W` est en secondes (arrondi au supérieur).
        let secondes = delai_ms.div_ceil(1000).max(1);
        cmd.args(["-c", "1", "-W", &secondes.to_string(), &ip_texte]);
    }

    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    match cmd.output() {
        Ok(sortie) => contient_reponse(&String::from_utf8_lossy(&sortie.stdout)),
        Err(_) => false,
    }
}

fn contient_reponse(texte: &str) -> bool {
    texte.to_ascii_lowercase().contains("ttl=")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnait_une_reponse_windows_francais() {
        assert!(contient_reponse(
            "Réponse de 192.168.1.1 : octets=32 temps<1ms TTL=64"
        ));
    }

    #[test]
    fn reconnait_une_reponse_linux() {
        assert!(contient_reponse("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.3 ms"));
    }

    #[test]
    fn rejette_hote_inaccessible() {
        // Windows renvoie code 0 même pour cette ligne : seul « TTL= » fait foi.
        assert!(!contient_reponse("Réponse de 192.168.1.5 : Impossible de joindre l'hôte de destination."));
        assert!(!contient_reponse("Request timed out."));
    }
}
