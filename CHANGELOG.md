# Changelog

Alle noemenswaardige wijzigingen in dit project staan in dit bestand.
Het formaat volgt [Keep a Changelog](https://keepachangelog.com/nl/1.1.0/) en de versienummers volgen [Semantic Versioning](https://semver.org/lang/nl/):

- **MAJOR**: wijzigingen die bestaand gebruik breken, zoals andere opties of een ander uitvoerformaat.
- **MINOR**: nieuwe functionaliteit, bijvoorbeeld nieuwe checks of een nieuwe richtlijnversie.
- **PATCH**: bugfixes.

## [Unreleased]

## [1.3.0] - 2026-10-20

### Toegevoegd
- Gecombineerd rapport `bevindingen.md` met rapportbevindingen in het sjabloonformaat. Velden: Scope, Category, Kill chain phase, Severity default, Description, Impact, Test approach, Remediation, Detection note, OWASP Top10 2025, WSTG, ASVS 5.0, MITRE ATTACK, CWE, PayloadsAllTheThings, OSCP plus, CISSP domain, Related IDs en Last updated. Daarna volgen Affected assets, Evidence (met reproductiecommando per asset), NCSC-referenties en eventueel een vraag aan de beheerder.
- Gerelateerde checklistpunten worden gekoppeld tot negen vaste bevindingen, zoals verouderde protocolversies, zwakke sleuteluitwisseling en zwakke cipher suites. Elke bevinding noemt alle getroffen assets en verwijst via Related IDs naar samenhangende bevindingen en CVE's.
- Severity wordt afgeleid van het NCSC-niveau en de uitbuitbaarheid: onvoldoende = High of Medium, uit te faseren = Low, advies = Info.
- Overzichtstabel, herstelvolgorde per asset en een bijlage met openstaande navraagpunten.
- `--id-template` voor het eigen ID-schema (bv. `AV-WEB-20.{n}`). `--report-from MAP` maakt het rapport uit eerdere runs, zonder opnieuw te scannen.

## [1.2.0] - 2026-10-20

### Toegevoegd
- Elk NAVRAAG-punt bevat de precieze vraag voor de beheerder en wat als voldoende antwoord telt volgens de richtlijn. De vraag staat in de console, bij het punt in de checklist en in de JSON (`question`, `acceptable_answer`).
- Nieuwe sectie "Vragenlijst voor de beheerder" onderaan de checklist: genummerde vragen met meetgegevens, verwijzing naar de richtlijn, het criterium en ruimte voor het antwoord, klaar om door te sturen.
- Bevindingen op niveau *uit te faseren* krijgen een vraag naar het uitfaseerplan (§3.2) met de concrete instellingen.
- Het navraagpunt over TLS-proxy's noemt een herkende CDN of proxy (Cloudflare, Akamai, F5, ...) uit de banners. Het punt over certificaatbeheer noemt de verloopdatum en de uitgever.

## [1.1.0] - 2026-10-20

### Toegevoegd
- Elk checklistpunt verwijst naar de passage in de richtlijn: paragraaf, tabel, paginanummer en de kern van de regel. De verwijzing staat in de console-uitvoer (bij bevindingen, adviezen en navraagpunten), in de checklist, in de bevindingentabel en in de JSON (`references`).
- Bevindingen op niveau *uit te faseren* verwijzen ook naar §3.2 (p. 16): de eis van een uitfaseerplan met meetbare criteria.

### Gewijzigd
- De DHE-bevinding maakt nu onderscheid tussen DHE-cipher suites in TLS 1.2 en finite-field-groepen die de server in TLS 1.3 accepteert. In het tweede geval staat erbij waar je dat aanpast.

## [1.0.0] - 2026-10-20

### Toegevoegd
- Toetsing van TLS-diensten aan de NCSC TLS-beveiligingsrichtlijnen versie 2025-05: versies, certificaat en authenticatie, sleuteluitwisseling, bulkversleuteling en hashing, overige opties, randvoorwaarden en quantumgereedheid.
- Beoordeling van elke cipher suite volgens Bijlage B, waarbij het zwakste onderdeel het niveau bepaalt.
- Aanvullende probes met OpenSSL 3.5+:
  - hybride post-quantum sleuteluitwisseling (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024);
  - verwerking van een grote ClientHello;
  - 0-RTT / early data.
- Opzoeken van TLSA/DANE-records met `dig`, met DNSSEC-validatie via `delv`.
- Poortontdekking met nmap (`--discover`) of een bestaande nmap-XML (`--nmap-xml`), inclusief automatische STARTTLS-detectie.
- Uitvoer per dienst als Markdown-checklist en als JSON, plus `overzicht.md` bij meerdere diensten.

[Unreleased]: https://github.com/mothproof3512/ncsc-tls-check/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/mothproof3512/ncsc-tls-check/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mothproof3512/ncsc-tls-check/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mothproof3512/ncsc-tls-check/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mothproof3512/ncsc-tls-check/releases/tag/v1.0.0
