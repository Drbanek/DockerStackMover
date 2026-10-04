# DockerStackMover 2.1

**Čeština** | [English](README.en.md)

DockerStackMover (DSM) je webový management a migrační systém pro Docker Compose infrastrukturu nad Portainerem. Verze 2.1 spojuje provisioning serverů, správu lokalit, WireGuard management, monitoring kapacity, migraci stacků a persistentních dat, proxy/DNS cutover, snapshoty a rollback do jednoho rozhraní.

> V2 princip: DSM migraci řídí, ale velká data netečou přes MGMT. Persistentní volumes se mezi NODE servery kopírují přímo přes LAN nebo WireGuard.

## Hlavní funkce v2.0

- bootstrap MGMT a webový first-run setup
- příprava první infrastruktury a Portaineru z UI
- více lokalit, SSH discovery a provisioning NODE/PROXY
- tři role: CONTROL (MGMT + Portainer + WireGuard HUB), PROXY a NODE
- automatická instalace Dockeru, Portainer Agentu, Capacity Agentu a Traefiku podle role
- centrální WireGuard management síť a management firewall
- DATA disk /srv, XFS project quota a Docker persistentní volumes na /srv/docker-volumes
- dashboard stacků/NODE a kapacitní monitoring
- Server Readiness kontroly
- pre-flight kontrola kolizí stacků, volumes a portů
- automatický Host IP rewrite při migraci
- snapshot persistentních volumes před migrací
- přímý NODE → NODE přenos: LAN ve stejné lokalitě, WireGuard mezi lokalitami
- předběžné změření volumes, živé MB a progress bar po 0,5 s; dokončený krok vždy 100 %
- vytvoření cílového stacku a kontrola container/health stavu
- Traefik proxy cutover a volitelný Váš Hosting DNS cutover
- automatické obnovení zdroje při chybě
- explicitní potvrzení nebo rollback po úspěšné migraci
- historie migrací/snapshotů v SQLite
- uživatelé, oprávnění, session a CSRF ochrana
- samoaktualizace z GHCR
- čeština / angličtina

## Doporučená struktura

~~~text
Internet -> veřejná IP -> PROXY (.10 / Traefik) -> NODE (.11-.29)
                         |
CONTROL/MGMT (.9) -> DSM + Portainer + WireGuard HUB (10.200.0.1) -> všechny lokality

NODE:
SYSTEM disk -> /var/lib/docker (engine, images, overlay)
DATA disk   -> /srv/docker-volumes
               ^ bind mount do /var/lib/docker/volumes
~~~

Adresní konvence: CONTROL/MGMT .9, PROXY .10, NODE .11-.29. CONTROL používá WireGuard 10.200.0.1; lokality používají management rozsah 10.200.<lokalita>.<suffix>. Každá lokalita může mít vlastní PROXY a produkční LAN nemusí být mezi lokalitami routovaná.

## Storage model NODE

Persistentní data jsou fyzicky na DATA disku. Docker dál používá standardní named volumes díky bind mountu:

~~~text
/srv/docker-volumes /var/lib/docker/volumes none bind 0 0
~~~

Provisioning připravuje DATA disk jako XFS s project quota. SYSTEM disk zůstává pro Docker engine, image, container layers a cache.

## Jak probíhá migrace

1. Pre-flight cíle a kontrola kolizí.
2. Změření persistentních volumes.
3. Zastavení zdrojového stacku.
4. Lokální snapshot volumes na zdrojovém NODE.
5. Vytvoření cílových volumes.
6. Přímý NODE → NODE přenos; LAN uvnitř lokality, WireGuard mezi lokalitami.
7. Live MB/celkem MB a procentní progress.
8. Vytvoření cílového Portainer stacku a Host IP rewrite.
9. Ověření containerů a healthchecku.
10. Proxy cutover a podle konfigurace DNS cutover.
11. Zdroj zůstává zastavený pro rollback.
12. Správce zvolí Potvrdit migraci nebo Vrátit zpět.

Velká data nejdou přes DSM backend. Helper kontejnery na NODE používají stream tar | nc | tar. Při chybě se DSM pokusí obnovit původní zdroj.

## První nasazení

Na čistém Ubuntu Serveru určeném pro MGMT:

~~~bash
curl -fsSL https://raw.githubusercontent.com/Drbanek/DockerStackMover/main/install.sh | sudo bash
~~~

Instalátor připraví Docker, WireGuard identitu MGMT, bezpečné host helpery, DSM z GHCR a standardizuje CONTROL/MGMT na LAN suffix .9 a připraví centrální WireGuard HUB 10.200.0.1. UI je standardně na portu 8082. Při změně IP může být SSH spojení ukončeno; pokračuje se na nové .9 adrese.

Po prvním přihlášení vytvoř administrátora a v Nastavení → Infrastruktura dokonči CONTROL infrastrukturu a inicializaci Portaineru. Další lokality a NODE/PROXY se nasazují přes Provisioning infrastruktury V2.

## Provisioning

Lokalita obsahuje název, LAN subnet, management octet, volitelnou veřejnou IP a SSH uživatele. DSM umí vyhledat SSH servery, identifikovat je, zkontrolovat disky a provisioning provést pro více vybraných serverů.

NODE provisioning zahrnuje LAN/hostname, WireGuard, DATA disk, Docker, Portainer Agent, Capacity Agent, firewall, test management cesty a registraci endpointu do Portaineru.

## Síť, proxy a DNS

Management služby jsou omezené vlastní nftables tabulkou. Typicky Portainer Agent používá TCP/9001, Capacity Agent TCP/9100 a DSM UI TCP/8082. DSM záměrně nenačítá globální nftables ruleset, aby nepoškodil Docker DOCKER-* chains.

PROXY používá Traefik. Při cross-site migraci může DSM po healthchecku změnit A záznam přes Váš Hosting API; rollback obnoví původní DNS.

## Aktualizace

~~~bash
sudo bash -c 'cd /opt/dockerstackmover && docker compose pull dockerstackmover && docker compose up -d --no-deps dockerstackmover'
~~~

Aktualizaci lze spustit také z Nastavení → Systém.

## CI / GHCR

Push do main validuje Python, shell skripty a Compose, sestaví DSM + Capacity Agent a publikuje latest a sha image. Tag v2.0.0 navíc publikuje:

~~~text
ghcr.io/drbanek/dockerstackmover:v2.0.0
ghcr.io/drbanek/dockerstackmover-capacity-agent:v2.0.0
~~~

## Struktura repozitáře

~~~text
app/                  backend + web UI
app/routes/           general, migration, capacity, provisioning
app/static/           UI, migrace, DNS, users, i18n
agent/                Capacity Agent
install/              bootstrap/WireGuard pomocné skripty
docs/                 deployment dokumentace
.github/workflows/    CI a GHCR publish
install.sh            první MGMT bootstrap
docker-compose.yml    kontejnerové nasazení
~~~

## Release 2.0.0

2.0.0 je první kompletní infrastrukturní release DSM. Podrobný popis architektury, nasazení, provozu a release notes je v [RELEASE-2.0.0.md](RELEASE-2.0.0.md).

## Licence

MIT License — Copyright (c) 2026 Lukáš Kačírek.
