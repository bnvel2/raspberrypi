//! Liste des dossiers partagés (SMB) d'une machine Windows, via l'API NetShareEnum.
//!
//! Cette fonction n'est disponible que sous Windows. Elle s'exécute avec l'identité
//! de l'utilisateur courant : si la machine distante refuse, l'erreur est affichée.

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Partage {
    pub nom: String,
    pub genre: &'static str,
    pub commentaire: String,
}

#[allow(dead_code)]
pub fn genre_depuis_type(t: u32) -> &'static str {
    // Les 16 bits de poids faible donnent le genre ; 0x80000000 = partage spécial (ex. C$).
    let base = match t & 0xFFFF {
        0 => "disque",
        1 => "imprimante",
        2 => "périphérique",
        3 => "IPC",
        _ => "autre",
    };
    base
}

#[cfg(not(windows))]
pub fn lister(_ip: Ipv4Addr) -> Result<Vec<Partage>, String> {
    Err("énumération des partages disponible uniquement sous Windows".to_string())
}

#[cfg(windows)]
pub fn lister(ip: Ipv4Addr) -> Result<Vec<Partage>, String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, MAX_PREFERRED_LENGTH,
    };
    use windows_sys::Win32::Storage::FileSystem::{NetShareEnum, SHARE_INFO_1};

    let serveur: Vec<u16> = format!("\\\\{ip}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut tampon: *mut u8 = std::ptr::null_mut();
    let mut lus: u32 = 0;
    let mut total: u32 = 0;
    let mut reprise: u32 = 0;

    let code = unsafe {
        NetShareEnum(
            serveur.as_ptr(),
            1,
            &mut tampon,
            MAX_PREFERRED_LENGTH,
            &mut lus,
            &mut total,
            &mut reprise,
        )
    };
    // 0 = succès ; 234 = ERROR_MORE_DATA (données partielles exploitables).
    if code != 0 && code != 234 {
        return Err(format!("NetShareEnum a échoué (code Windows {code})"));
    }

    let mut resultat = Vec::new();
    if !tampon.is_null() {
        let elements = unsafe { std::slice::from_raw_parts(tampon as *const SHARE_INFO_1, lus as usize) };
        for e in elements {
            resultat.push(Partage {
                nom: unsafe { texte_large(e.shi1_netname) },
                genre: genre_depuis_type(e.shi1_type),
                commentaire: unsafe { texte_large(e.shi1_remark) },
            });
        }
        unsafe { NetApiBufferFree(tampon as *const core::ffi::c_void) };
    }
    Ok(resultat)
}

/// Convertit une chaîne Windows UTF-16 terminée par 0 en `String`.
///
/// # Safety
/// `p` doit être nul ou pointer vers une chaîne UTF-16 terminée par 0.
#[cfg(windows)]
unsafe fn texte_large(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut longueur = 0usize;
    while *p.add(longueur) != 0 {
        longueur += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, longueur))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genres() {
        assert_eq!(genre_depuis_type(0), "disque");
        assert_eq!(genre_depuis_type(0x8000_0000), "disque"); // C$ : disque spécial
        assert_eq!(genre_depuis_type(1), "imprimante");
        assert_eq!(genre_depuis_type(0x8000_0003), "IPC"); // IPC$
    }
}
