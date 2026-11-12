//! Fabricant d'une carte réseau d'après les 3 premiers octets de son adresse MAC (OUI).
//!
//! Le programme embarque seulement une très courte liste d'exemples.
//! Pour une couverture complète, téléchargez la base publique de l'IEEE
//! (fichier « oui.txt » ou « oui.csv ») ou le fichier « manuf » de Wireshark,
//! puis passez-le avec l'option --oui.

use crate::arp::Mac;
use std::collections::HashMap;
use std::io;
use std::path::Path;

pub struct BaseOui {
    table: HashMap<u32, String>,
}

/// Quelques OUI bien connus, uniquement pour que la démonstration fonctionne hors ligne.
const EXEMPLES: &[(u32, &str)] = &[
    (0x00000C, "Cisco Systems"),
    (0x000C29, "VMware"),
    (0x005056, "VMware"),
    (0x00155D, "Microsoft (Hyper-V)"),
    (0x080027, "PCS Systems (VirtualBox)"),
    (0xB827EB, "Raspberry Pi Foundation"),
    (0xDCA632, "Raspberry Pi Trading"),
];

impl BaseOui {
    pub fn integree() -> Self {
        let table = EXEMPLES.iter().map(|(k, v)| (*k, v.to_string())).collect();
        BaseOui { table }
    }

    /// Charge un fichier IEEE (txt ou csv) ou Wireshark. Retourne le nombre d'entrées lues.
    pub fn charger_fichier(&mut self, chemin: &Path) -> io::Result<usize> {
        let octets = std::fs::read(chemin)?;
        let texte = String::from_utf8_lossy(&octets);
        let mut n = 0;
        for ligne in texte.lines() {
            if let Some((cle, nom)) = analyser_ligne(ligne) {
                self.table.insert(cle, nom);
                n += 1;
            }
        }
        Ok(n)
    }

    pub fn fabricant(&self, mac: &Mac) -> Option<String> {
        // Bit 1 du premier octet = adresse administrée localement (aléatoire, VM, etc.).
        if mac[0] & 0x02 != 0 {
            let cle = u32::from_be_bytes([0, mac[0], mac[1], mac[2]]);
            return Some(
                self.table
                    .get(&cle)
                    .cloned()
                    .unwrap_or_else(|| "(adresse administrée localement)".to_string()),
            );
        }
        let cle = u32::from_be_bytes([0, mac[0], mac[1], mac[2]]);
        self.table.get(&cle).cloned()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.table.len()
    }
}

fn cle_depuis_hex(texte: &str) -> Option<u32> {
    let propre: String = texte.chars().filter(|c| *c != ':' && *c != '-').collect();
    if propre.len() != 6 {
        return None;
    }
    u32::from_str_radix(&propre, 16).ok()
}

/// Reconnaît trois formats : IEEE txt, IEEE csv, Wireshark « manuf ».
fn analyser_ligne(ligne: &str) -> Option<(u32, String)> {
    let ligne = ligne.trim_end_matches(['\r', '\n']);
    if ligne.is_empty() || ligne.starts_with('#') {
        return None;
    }
    // IEEE oui.csv : « MA-L,000000,Xerox Corporation,adresse »
    if let Some(reste) = ligne.strip_prefix("MA-L,") {
        let (hex, reste) = reste.split_once(',')?;
        let cle = cle_depuis_hex(hex)?;
        let nom = if let Some(entre_guillemets) = reste.strip_prefix('"') {
            entre_guillemets.split('"').next()?.to_string()
        } else {
            reste.split(',').next()?.to_string()
        };
        return Some((cle, nom.trim().to_string()));
    }
    // IEEE oui.txt : « 00-00-0C   (hex)\t\tCisco Systems, Inc »
    if let Some((gauche, droite)) = ligne.split_once("(hex)") {
        let cle = cle_depuis_hex(gauche.trim())?;
        return Some((cle, droite.trim().to_string()));
    }
    // Wireshark manuf : « 00:00:0C\tCisco\tCisco Systems, Inc »
    let champs: Vec<&str> = ligne.split('\t').collect();
    if champs.len() >= 2 {
        let cle = cle_depuis_hex(champs[0].trim())?;
        let nom = champs
            .iter()
            .skip(1)
            .rev()
            .find(|c| !c.trim().is_empty())?
            .trim();
        return Some((cle, nom.to_string()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ieee_txt() {
        let (k, n) = analyser_ligne("00-00-0C   (hex)\t\tCisco Systems, Inc").unwrap();
        assert_eq!(k, 0x00000C);
        assert_eq!(n, "Cisco Systems, Inc");
    }

    #[test]
    fn format_ieee_csv() {
        let (k, n) = analyser_ligne("MA-L,000000,Xerox Corporation,M/S 105-50C").unwrap();
        assert_eq!((k, n.as_str()), (0x000000, "Xerox Corporation"));
        let (k, n) = analyser_ligne("MA-L,00000C,\"Cisco Systems, Inc\",170 West Tasman").unwrap();
        assert_eq!((k, n.as_str()), (0x00000C, "Cisco Systems, Inc"));
    }

    #[test]
    fn format_wireshark() {
        let (k, n) = analyser_ligne("00:00:0C\tCisco\tCisco Systems, Inc").unwrap();
        assert_eq!((k, n.as_str()), (0x00000C, "Cisco Systems, Inc"));
        let (k, n) = analyser_ligne("00:00:01\tXerox").unwrap();
        assert_eq!((k, n.as_str()), (1, "Xerox"));
    }

    #[test]
    fn lignes_ignorees() {
        assert!(analyser_ligne("# commentaire").is_none());
        assert!(analyser_ligne("").is_none());
        assert!(analyser_ligne("n'importe quoi").is_none());
        // Les entrées plus fines que /24 (ex. 00:55:DA:00:00:00/28) sont ignorées.
        assert!(analyser_ligne("00:55:DA:00:00:00/28\tShinko").is_none());
    }

    #[test]
    fn recherche() {
        let base = BaseOui::integree();
        assert!(base.len() >= 5);
        assert_eq!(
            base.fabricant(&[0x00, 0x00, 0x0C, 1, 2, 3]).as_deref(),
            Some("Cisco Systems")
        );
        assert_eq!(base.fabricant(&[0x00, 0x11, 0x22, 1, 2, 3]), None);
        // 0x52 = bit « administrée localement » positionné
        assert_eq!(
            base.fabricant(&[0x52, 0x54, 0x00, 1, 2, 3]).as_deref(),
            Some("(adresse administrée localement)")
        );
    }
}
