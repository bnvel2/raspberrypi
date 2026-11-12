//! Adresse MAC d'une machine du réseau local.
//!
//! L'ARP ne traverse pas les routeurs : on ne peut connaître la MAC que des
//! machines situées dans le même réseau local que le poste qui scanne.

use std::net::Ipv4Addr;

pub type Mac = [u8; 6];

pub fn formater(mac: &Mac) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Windows : requête ARP directe via l'API `SendARP` (iphlpapi).
#[cfg(windows)]
pub fn mac_de(ip: Ipv4Addr) -> Option<Mac> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

    // IPAddr est un entier dont l'ordre des octets en mémoire est celui du réseau.
    let destination = u32::from_ne_bytes(ip.octets());
    let mut tampon = [0u8; 8];
    let mut longueur: u32 = tampon.len() as u32;
    let code = unsafe {
        SendARP(
            destination,
            0,
            tampon.as_mut_ptr() as *mut core::ffi::c_void,
            &mut longueur,
        )
    };
    if code == 0 && longueur >= 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&tampon[..6]);
        if mac != [0u8; 6] {
            return Some(mac);
        }
    }
    None
}

/// Linux : lecture du cache ARP du noyau, rempli par les connexions déjà faites.
#[cfg(target_os = "linux")]
pub fn mac_de(ip: Ipv4Addr) -> Option<Mac> {
    let contenu = std::fs::read_to_string("/proc/net/arp").ok()?;
    lire_proc_arp(&contenu, ip)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn mac_de(_ip: Ipv4Addr) -> Option<Mac> {
    None
}

/// Analyse le contenu de /proc/net/arp. Fonction pure, donc testable partout.
#[allow(dead_code)]
pub fn lire_proc_arp(contenu: &str, ip: Ipv4Addr) -> Option<Mac> {
    let cherchee = ip.to_string();
    for ligne in contenu.lines().skip(1) {
        let champs: Vec<&str> = ligne.split_whitespace().collect();
        // IP address, HW type, Flags, HW address, Mask, Device
        if champs.len() >= 4 && champs[0] == cherchee && champs[2] != "0x0" {
            return analyser_mac(champs[3]);
        }
    }
    None
}

#[allow(dead_code)]
fn analyser_mac(texte: &str) -> Option<Mac> {
    let morceaux: Vec<&str> = texte.split(':').collect();
    if morceaux.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, m) in morceaux.iter().enumerate() {
        mac[i] = u8::from_str_radix(m, 16).ok()?;
    }
    if mac == [0u8; 6] {
        None
    } else {
        Some(mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXEMPLE: &str = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n\
192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        eth0\n";

    #[test]
    fn trouve_une_entree_valide() {
        let mac = lire_proc_arp(EXEMPLE, Ipv4Addr::new(192, 168, 1, 1)).unwrap();
        assert_eq!(formater(&mac), "AA:BB:CC:DD:EE:01");
    }

    #[test]
    fn ignore_entree_incomplete_et_absente() {
        assert!(lire_proc_arp(EXEMPLE, Ipv4Addr::new(192, 168, 1, 7)).is_none());
        assert!(lire_proc_arp(EXEMPLE, Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }
}
