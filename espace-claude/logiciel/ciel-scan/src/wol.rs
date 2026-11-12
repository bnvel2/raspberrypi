//! Wake-on-LAN : « paquet magique » envoyé en diffusion UDP (port 9).
//! Le paquet contient 6 octets 0xFF suivis de 16 répétitions de l'adresse MAC.

use crate::arp::Mac;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

pub fn analyser_mac(texte: &str) -> Result<Mac, String> {
    let morceaux: Vec<&str> = texte.trim().split([':', '-']).collect();
    if morceaux.len() != 6 {
        return Err(format!(
            "adresse MAC invalide : « {texte} » (attendu : AA:BB:CC:DD:EE:FF)"
        ));
    }
    let mut mac = [0u8; 6];
    for (i, m) in morceaux.iter().enumerate() {
        mac[i] = u8::from_str_radix(m, 16)
            .map_err(|_| format!("adresse MAC invalide : « {texte} »"))?;
    }
    Ok(mac)
}

pub fn paquet_magique(mac: &Mac) -> Vec<u8> {
    let mut paquet = vec![0xFFu8; 6];
    for _ in 0..16 {
        paquet.extend_from_slice(mac);
    }
    paquet
}

pub fn envoyer(mac: &Mac, diffusion: Ipv4Addr) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.send_to(&paquet_magique(mac), (diffusion, 9))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_deux_notations() {
        assert_eq!(analyser_mac("aa:bb:cc:dd:ee:ff").unwrap(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(analyser_mac("AA-BB-CC-DD-EE-FF").unwrap(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(analyser_mac("AA:BB:CC").is_err());
        assert!(analyser_mac("ZZ:BB:CC:DD:EE:FF").is_err());
    }

    #[test]
    fn paquet_de_102_octets() {
        let mac = [1, 2, 3, 4, 5, 6];
        let p = paquet_magique(&mac);
        assert_eq!(p.len(), 102);
        assert!(p[..6].iter().all(|&b| b == 0xFF));
        assert_eq!(&p[6..12], &mac);
        assert_eq!(&p[96..102], &mac);
    }
}
