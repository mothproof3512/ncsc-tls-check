# ncsc_tls_check.py

Toetst een TLS-dienst aan de **NCSC TLS-beveiligingsrichtlijnen versie 2025-05** en schrijft per host een ingevulde checklist weg. De indeling volgt de pentestchecklist (versies, certificaat, sleuteluitwisseling, ciphers, opties, implementatie, quantum).

## Installatie op Kali

```bash
sudo apt update && sudo apt install -y testssl.sh nmap bind9-dnsutils
chmod +x ncsc_tls_check.py
openssl version        # 3.5 of hoger nodig voor de post-quantum probes
```

- Python 3.8+ (alleen standaardbibliotheek).
- **testssl.sh 3.2 of nieuwer**. Op Kali vindt het script `testssl` vanzelf. Oudere versies rapporteren geen KEMs en sig_algs; die punten worden dan `ONBEKEND`.
- **OpenSSL 3.5+** voor de post-quantum probes (hybride KEM, grote ClientHello). Met een oudere OpenSSL draait de rest gewoon.
- **nmap** voor `--discover`.
- `dig` voor TLSA/DANE, optioneel `delv` voor DNSSEC-validatie.

## Gebruik

```bash
./ncsc_tls_check.py example.com --discover                      # nmap zoekt alle TLS- en STARTTLS-poorten, toetst ze allemaal
./ncsc_tls_check.py example.com --discover --ports 1-1024,8443  # sneller: beperkte poortrange
./ncsc_tls_check.py --nmap-xml enum/nmap_full.xml               # bestaande nmap -oX uit je enumeratie hergebruiken
./ncsc_tls_check.py example.com                                 # alleen HTTPS op 443
./ncsc_tls_check.py example.com --ip 192.0.2.10                 # specifiek IP
./ncsc_tls_check.py mail.example.com:25 -t smtp                 # één STARTTLS-dienst
./ncsc_tls_check.py -f targets.txt -o resultaten/               # meerdere hosts
./ncsc_tls_check.py example.com --json scan.json                # bestaande testssl --jsonfile beoordelen
```

**Poortontdekking.** Met `--discover` draait het script `nmap -Pn -sV --open -p 1-65535 -T4` en toetst daarna elke gevonden dienst:
- direct TLS: https, imaps, smtps, ldaps, en alles wat nmap herkent als `ssl/...`;
- STARTTLS, automatisch met de juiste `-t`: smtp/submission, imap, pop3, ftp, xmpp, ldap, postgres, mysql, nntp, sieve, irc.

Een volledige `-p-` met `-sV` kan lang duren. Heb je tijdens de enumeratie al een nmap-scan met `-sV -oX` gedraaid, gebruik die dan via `--nmap-xml`. Zonder target toetst het script dan alle hosts in die XML.

Als de scan van een STARTTLS-dienst mislukt, staat dat in het overzicht. Vaak betekent het dat de dienst geen STARTTLS aanbiedt en dus onversleuteld communiceert. Controleer dat handmatig.

Het script draait testssl.sh met `-p -s -f -P -S -h -U` (geen client-simulaties). Een scan duurt een paar minuten per poort.

## Uitvoer per host

| Bestand | Inhoud |
| --- | --- |
| `<host>_<poort>_ncsc.md` | De checklist met `[x]`/`[ ]`, het NCSC-niveau, de gemeten waarde, advies en de verwijzing naar de richtlijn, plus een tabel met bevindingen voor de rapportage |
| `<host>_<poort>_ncsc.json` | Dezelfde resultaten machineleesbaar, inclusief het niveau per cipher suite |
| `<host>_<poort>_testssl.json/.log` | De ruwe testssl-uitvoer als bewijs |
| `<host>_nmap.xml` | De nmap-uitvoer (bij `--discover`) |
| `overzicht.md` | Eén regel per dienst: aantal bevindingen, zwakste niveau, link naar de checklist (bij meerdere diensten of `--discover`) |

Het script stopt met exitcode 1 zodra er minstens één bevinding is, zodat je het in een pipeline kunt gebruiken.

## Verwijzingen naar de richtlijn

Bij elk checklistpunt staat de passage uit de richtlijn waarop de beoordeling is gebaseerd, met paginanummer, bijvoorbeeld:

```
BEVINDING Alleen AEAD-ciphers (GCM, CCM, ChaCha20-Poly1305); geen CBC [uit te faseren]
          4 CBC-suite(s): ...
          Richtlijn: §3.3.4 Algoritmes voor bulkversleuteling, Tabel 8 en toelichting (p. 20-21)
          Richtlijn: §3.2 Richtlijn voor een veilige TLS-configuratie (p. 16)
```

De checklist en de JSON bevatten daarnaast de kern van de regel in een zin. De paginanummers horen bij versie 2025-05 van de richtlijn.

## Statussen

| Status | Betekenis |
| --- | --- |
| `OK` `[x]` | goed, voldoende of n.v.t. |
| `BEVINDING` | uit te faseren of onvoldoende volgens de richtlijn |
| `ADVIES` | aanbeveling, geen harde eis (bv. OCSP-stapling, DANE, hybride PQ) |
| `NAVRAAG` | niet extern meetbaar; navragen bij de beheerder |
| `ONBEKEND` | niet gemeten (tool te oud, probe overgeslagen); handmatig aanvullen |

## Beoordelingsregels

- Een cipher suite krijgt het niveau van het zwakste onderdeel (Bijlage B).
- RSA-PKCS#1 v1.5 in de TLS 1.2-handtekeningalgoritmes telt als **onvoldoende** (Tabel 4). Houd rekening met oudere clients.
- Een DH-groep die niet uit RFC 7919 komt (bv. RFC 3526 Oakley 16) wordt beoordeeld op bitgrootte. Daarbij komt een opmerking.
- Een certificaatketen die alleen in Java faalt, terwijl Mozilla, Microsoft en Apple hem accepteren, wordt `ADVIES` in plaats van een bevinding.
- Sessiehervatting in TLS 1.2 is alleen voldoende met aanvullende beschermingsmaatregelen, dus dat punt staat altijd op `NAVRAAG`.

Gebruik het script alleen op systemen waarvoor je toestemming hebt om te testen.

## Versies

Het project gebruikt [Semantic Versioning](https://semver.org/lang/nl/). Elke release heeft een git-tag (`v1.0.0`, ...) en staat beschreven in [CHANGELOG.md](CHANGELOG.md). Het versienummer van je kopie zie je met `./ncsc_tls_check.py --version`; het staat ook in elke gegenereerde checklist.

Een nieuwe versie uitbrengen:

1. Pas `__version__` aan in `ncsc_tls_check.py`.
2. Verplaats de punten onder `[Unreleased]` in `CHANGELOG.md` naar een nieuwe versiekop.
3. Commit, tag en push:
   ```bash
   git commit -am "Versie 1.1.0"
   git tag -a v1.1.0 -m "Versie 1.1.0"
   git push && git push --tags
   ```
