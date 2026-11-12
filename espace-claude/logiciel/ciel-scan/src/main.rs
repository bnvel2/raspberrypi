//! ciel-scan : scanner réseau pédagogique (bac pro CIEL).
//!
//! Programme écrit de zéro à partir de protocoles publics (ICMP, ARP, TCP, DNS,
//! SNMP, SMB, Wake-on-LAN). Il ne reprend ni code ni fichier de données
//! d'un logiciel tiers.

mod arp;
mod cible;
mod oui;
mod ping;
mod ports;
mod shares;
mod snmp;
mod wol;

use clap::{Args, Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "ciel-scan",
    version,
    about = "Scanner réseau pédagogique (bac pro CIEL). N'analysez que des réseaux dont vous avez l'autorisation."
)]
struct Cli {
    #[command(subcommand)]
    commande: Commande,
}

#[derive(Subcommand)]
enum Commande {
    /// Détecte les machines d'une cible et collecte leurs informations
    Scan(ArgsScan),
    /// Envoie un paquet Wake-on-LAN (réveil réseau) à une adresse MAC
    Wol(ArgsWol),
}

#[derive(Args)]
struct ArgsScan {
    /// Cible : 192.168.1.10, 192.168.1.0/24, 192.168.1.10-50, ou une liste séparée par des virgules
    cible: String,
    /// Ports TCP à tester : « defaut », ou une liste comme 22,80,8000-8010
    #[arg(long, default_value = "defaut")]
    ports: String,
    /// Délai d'attente par test, en millisecondes
    #[arg(long, default_value_t = 400)]
    delai_ms: u64,
    /// Nombre de machines analysées en parallèle
    #[arg(long, default_value_t = 64)]
    threads: usize,
    /// Base des fabricants (IEEE oui.txt / oui.csv, ou « manuf » de Wireshark)
    #[arg(long, value_name = "FICHIER")]
    oui: Option<PathBuf>,
    /// Interroge SNMP v2c ; communauté facultative (« public » par défaut)
    #[arg(long, value_name = "COMMUNAUTE", num_args = 0..=1, default_missing_value = "public")]
    snmp: Option<String>,
    /// Liste les dossiers partagés (SMB) des machines qui ont le port 445 ouvert (Windows)
    #[arg(long)]
    partages: bool,
    /// Enregistre le résultat dans un fichier CSV (séparateur « ; », lisible par Excel)
    #[arg(long, value_name = "FICHIER")]
    csv: Option<PathBuf>,
    /// Affiche aussi les adresses qui ne répondent pas
    #[arg(long)]
    tout: bool,
    /// Autorise l'analyse d'adresses publiques (uniquement avec l'accord écrit du propriétaire)
    #[arg(long)]
    autoriser_public: bool,
}

#[derive(Args)]
struct ArgsWol {
    /// Adresse MAC de la machine à réveiller (AA:BB:CC:DD:EE:FF)
    mac: String,
    /// Adresse de diffusion du réseau (par défaut 255.255.255.255)
    #[arg(long, default_value = "255.255.255.255")]
    diffusion: Ipv4Addr,
}

struct Reglages {
    ports: Vec<u16>,
    delai_ms: u64,
    oui: oui::BaseOui,
    snmp: Option<String>,
    partages: bool,
}

struct Hote {
    ip: Ipv4Addr,
    ping: bool,
    ports: Vec<u16>,
    nom: Option<String>,
    mac: Option<arp::Mac>,
    fabricant: Option<String>,
    snmp: Option<snmp::InfoSnmp>,
    partages: Option<Result<Vec<shares::Partage>, String>>,
}

impl Hote {
    fn en_ligne(&self) -> bool {
        self.ping || !self.ports.is_empty()
    }
}

fn sonder(ip: Ipv4Addr, cfg: &Reglages) -> Hote {
    let delai = Duration::from_millis(cfg.delai_ms.max(1));
    let mut h = Hote {
        ip,
        ping: ping::repond_au_ping(ip, cfg.delai_ms),
        ports: ports::ports_ouverts(ip, &cfg.ports, delai),
        nom: None,
        mac: None,
        fabricant: None,
        snmp: None,
        partages: None,
    };
    if !h.en_ligne() {
        return h;
    }
    h.nom = dns_lookup::lookup_addr(&IpAddr::V4(ip))
        .ok()
        .filter(|n| *n != ip.to_string());
    h.mac = arp::mac_de(ip);
    h.fabricant = h.mac.as_ref().and_then(|m| cfg.oui.fabricant(m));
    if let Some(communaute) = &cfg.snmp {
        h.snmp = snmp::interroger(ip, communaute, Duration::from_millis(cfg.delai_ms.max(1000)));
    }
    if cfg.partages && h.ports.contains(&445) {
        h.partages = Some(shares::lister(ip));
    }
    h
}

fn tronquer(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn ports_en_texte(p: &[u16]) -> String {
    p.iter()
        .map(|x| format!("{}/{}", x, ports::nom_service(*x)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn partages_en_texte(p: &Option<Result<Vec<shares::Partage>, String>>) -> String {
    match p {
        None => String::new(),
        Some(Err(e)) => format!("(erreur : {e})"),
        Some(Ok(v)) => v
            .iter()
            .map(|s| {
                if s.commentaire.is_empty() {
                    format!("{} [{}]", s.nom, s.genre)
                } else {
                    format!("{} [{}] {}", s.nom, s.genre, s.commentaire)
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// Protège contre l'« injection de formule » : un texte venant du réseau qui commence par
/// = + - @ serait interprété comme une formule par Excel.
fn champ_csv(s: &str) -> String {
    let mut texte = s.to_string();
    if texte.starts_with(['=', '+', '-', '@']) {
        texte.insert(0, '\'');
    }
    format!("\"{}\"", texte.replace('"', "\"\""))
}

fn ecrire_csv(chemin: &PathBuf, hotes: &[&Hote]) -> std::io::Result<()> {
    // Le BOM UTF-8 permet à Excel de lire correctement les accents.
    let mut sortie = String::from("\u{FEFF}IP;Nom;MAC;Fabricant;Ports;SNMP nom;SNMP description;Partages\r\n");
    for h in hotes {
        let (snmp_nom, snmp_desc) = match &h.snmp {
            Some(i) => (
                i.nom.clone().unwrap_or_default(),
                i.description.clone().unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };
        let champs = [
            h.ip.to_string(),
            h.nom.clone().unwrap_or_default(),
            h.mac.as_ref().map(arp::formater).unwrap_or_default(),
            h.fabricant.clone().unwrap_or_default(),
            ports_en_texte(&h.ports),
            snmp_nom,
            snmp_desc,
            partages_en_texte(&h.partages),
        ];
        let ligne: Vec<String> = champs.iter().map(|c| champ_csv(c)).collect();
        sortie.push_str(&ligne.join(";"));
        sortie.push_str("\r\n");
    }
    std::fs::write(chemin, sortie)
}

fn commande_scan(a: ArgsScan) -> Result<(), String> {
    let ips = cible::analyser_cibles(&a.cible)?;
    cible::verifier_perimetre(&ips, a.autoriser_public)?;
    let liste_ports = ports::analyser_ports(&a.ports)?;

    let mut base = oui::BaseOui::integree();
    if let Some(chemin) = &a.oui {
        let n = base
            .charger_fichier(chemin)
            .map_err(|e| format!("lecture de {} impossible : {e}", chemin.display()))?;
        eprintln!("Base des fabricants : {n} entrées chargées depuis {}", chemin.display());
    } else {
        eprintln!("Base des fabricants : liste d'exemples seulement (voir --oui pour la base complète).");
    }

    let cfg = Reglages {
        ports: liste_ports,
        delai_ms: a.delai_ms,
        oui: base,
        snmp: a.snmp.clone(),
        partages: a.partages,
    };

    eprintln!(
        "Analyse de {} adresse(s), {} port(s) par machine, {} machine(s) en parallèle…",
        ips.len(),
        cfg.ports.len(),
        a.threads.clamp(1, 512).min(ips.len())
    );

    let suivant = AtomicUsize::new(0);
    let resultats: Mutex<Vec<Hote>> = Mutex::new(Vec::new());
    let nb_threads = a.threads.clamp(1, 512).min(ips.len());
    std::thread::scope(|s| {
        for _ in 0..nb_threads {
            s.spawn(|| loop {
                let i = suivant.fetch_add(1, Ordering::Relaxed);
                if i >= ips.len() {
                    break;
                }
                let h = sonder(ips[i], &cfg);
                resultats.lock().unwrap().push(h);
            });
        }
    });
    let mut hotes = resultats.into_inner().unwrap();
    hotes.sort_by_key(|h| h.ip);

    let affiches: Vec<&Hote> = hotes.iter().filter(|h| a.tout || h.en_ligne()).collect();
    println!(
        "{:<16} {:<26} {:<17} {:<26} PORTS OUVERTS",
        "ADRESSE IP", "NOM", "MAC", "FABRICANT"
    );
    for h in &affiches {
        let etat = if h.en_ligne() { "" } else { "(pas de réponse)" };
        println!(
            "{:<16} {:<26} {:<17} {:<26} {}{}",
            h.ip,
            tronquer(h.nom.as_deref().unwrap_or("-"), 26),
            h.mac.as_ref().map(arp::formater).unwrap_or_else(|| "-".into()),
            tronquer(h.fabricant.as_deref().unwrap_or("-"), 26),
            ports_en_texte(&h.ports),
            etat
        );
        if let Some(info) = &h.snmp {
            println!(
                "    SNMP  nom : {}   description : {}",
                info.nom.as_deref().unwrap_or("-"),
                tronquer(info.description.as_deref().unwrap_or("-"), 80)
            );
        }
        match &h.partages {
            Some(Ok(v)) if !v.is_empty() => println!("    Partages : {}", partages_en_texte(&h.partages)),
            Some(Ok(_)) => println!("    Partages : aucun"),
            Some(Err(e)) => println!("    Partages : {e}"),
            None => {}
        }
    }
    let en_ligne = hotes.iter().filter(|h| h.en_ligne()).count();
    println!("\n{} machine(s) détectée(s) sur {} adresse(s) analysée(s).", en_ligne, ips.len());

    if let Some(chemin) = &a.csv {
        let a_ecrire: Vec<&Hote> = hotes.iter().filter(|h| a.tout || h.en_ligne()).collect();
        ecrire_csv(chemin, &a_ecrire)
            .map_err(|e| format!("écriture de {} impossible : {e}", chemin.display()))?;
        println!("Résultat enregistré dans {}", chemin.display());
    }
    Ok(())
}

fn commande_wol(a: ArgsWol) -> Result<(), String> {
    let mac = wol::analyser_mac(&a.mac)?;
    wol::envoyer(&mac, a.diffusion).map_err(|e| format!("envoi impossible : {e}"))?;
    println!(
        "Paquet Wake-on-LAN envoyé à {} via {}:9 (le réveil dépend de la carte réseau et du BIOS).",
        arp::formater(&mac),
        a.diffusion
    );
    Ok(())
}

#[cfg(windows)]
fn preparer_console() {
    // Affichage correct des accents dans la console Windows (UTF-8).
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleOutputCP(65001);
    }
}

#[cfg(not(windows))]
fn preparer_console() {}

fn main() {
    preparer_console();
    let cli = Cli::parse();
    let resultat = match cli.commande {
        Commande::Scan(a) => commande_scan(a),
        Commande::Wol(a) => commande_wol(a),
    };
    if let Err(e) = resultat {
        eprintln!("Erreur : {e}");
        std::process::exit(2);
    }
}
