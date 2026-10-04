# DockerStackMover v2.0.0

Datum vydání: 2026-10-04

DockerStackMover 2.0.0 posouvá původní migrátor Portainer stacků na kompletní management platformu pro více Docker lokalit.

## Architektura

DSM rozlišuje čtyři provozní role:

- **MGMT** — webové UI, konfigurace, SQLite stav a orchestrace.
- **PORTAINER / MAIN** — centrální Portainer a WireGuard HUB/management bod.
- **PROXY** — Traefik ingress pro danou lokalitu.
- **NODE** — aplikační Docker host s Portainer Agentem, Capacity Agentem a DATA diskem.

Doporučené LAN suffixy jsou .8 PORTAINER, .9 PROXY, .10 MGMT a .11-.29 NODE. Management WireGuard používá 10.200.<site>.<suffix>.

## Datová vrstva

NODE používá oddělený SYSTEM a DATA storage. Persistentní named volumes jsou fyzicky v /srv/docker-volumes a bind-mounted do /var/lib/docker/volumes. Docker Compose soubory tedy nemusí znát fyzické umístění DATA disku.

Provisioning DATA disku používá XFS a project quota.

## Provisioning

První MGMT se instaluje pomocí install.sh. Instalátor umí připravit Docker, WireGuard identitu, host-side helper pro konfiguraci WireGuardu, self-update bridge a DSM container.

Webové UI následně umí:
- first-run administrátora,
- připravit první PORTAINER/MAIN infrastrukturu,
- založit lokality,
- prohledat LAN na SSH,
- identifikovat servery,
- nabídnout DATA disky,
- přidělit hostname/LAN/management adresy,
- připravit WireGuard,
- instalovat Docker/Portainer Agent/Capacity Agent,
- připravit PROXY,
- aplikovat management firewall,
- otestovat MAIN → Agent cestu,
- registrovat endpoint do Portaineru.

## Migrace

Migrační pipeline:

1. Příprava a pre-flight.
2. Kontrola stack/volume/port kolizí.
3. Změření zdrojových volumes.
4. Zastavení zdroje.
5. Snapshot před migrací.
6. Přenos persistentních volumes.
7. Vytvoření cílového stacku.
8. Healthcheck cíle.
9. Proxy cutover.
10. DNS cutover, pokud je relevantní.
11. Dokončení s možností confirm/rollback.

### Přímý datový transport

Od v2 velké volume streamy neprocházejí přes MGMT/HTTP archive proxy.

- lokální snapshot: helper container na stejném NODE
- stejná lokalita: NODE → NODE po LAN
- jiná lokalita: NODE → NODE po WireGuardu

Helper kontejnery používají tar stream. DSM pouze vytváří helpery, sleduje stav a zapisuje průběh.

### Progress

Před kopírováním se změří očekávaná velikost. UI každých 0,5 s zobrazuje přenesené MB, očekávané MB a progress bar. Běžící krok je omezen na 99 % a až úspěšné dokončení jej nastaví přesně na 100 %, protože filesystem/tar accounting nemusí během přenosu přesně odpovídat počátečnímu du.

### Bezpečné dokončení

Po úspěšné migraci se zdroj nemaže. Zůstává zastavený pro rollback.

- **Potvrdit migraci** — odstraní starou zdrojovou kopii.
- **Vrátit zpět** — odstraní cílovou kopii a spustí původní zdroj.
- chyba během migrace — DSM se pokusí zdroj automaticky obnovit.

## Proxy a DNS

PROXY role používá Traefik. DSM umí stacku přiřadit doménu/HTTPS a při migraci připravit backend na cílový NODE.

Integrace Váš Hosting umožňuje cross-site A-record cutover. DNS změna probíhá až po ověření cíle a rollback vrací původní stav.

## Monitoring a readiness

Capacity Agent poskytuje kapacitní data NODE serverů pro dashboard a výběr cíle. Server Readiness slouží k ověření připravenosti jednotlivých rolí a management cest.

## Bezpečnost

- uživatelské účty a oprávnění
- PBKDF2 hash hesel
- session + CSRF
- WireGuard management
- management firewall
- úzké host-side helpery namísto Docker socketu v DSM containeru
- zachování zdroje do explicitního potvrzení
- persistentní konfigurace v /data

## Fresh install

~~~bash
curl -fsSL https://raw.githubusercontent.com/Drbanek/DockerStackMover/main/install.sh | sudo bash
~~~

Po bootstrapu otevři DSM UI na MGMT:8082, dokonči first-run účet a pokračuj v Nastavení → Infrastruktura.

## Upgrade existující instalace

~~~bash
sudo bash -c 'cd /opt/dockerstackmover && docker compose pull dockerstackmover && docker compose up -d --no-deps dockerstackmover'
~~~

Před významným upgradem je doporučená záloha persistentního DSM data volume.

## Container images

Release tag publikuje:

~~~text
ghcr.io/drbanek/dockerstackmover:v2.0.0
ghcr.io/drbanek/dockerstackmover-capacity-agent:v2.0.0
~~~

Průběžná větev main publikuje také latest a sha-<commit>.

## Požadavky

- Ubuntu Server pro automatizovaný provisioning/bootstrap
- Docker Engine / Compose
- Portainer
- SSH přístup pro provisioning
- síťová dostupnost management služeb podle role
- WireGuard pro centrální management a cross-site přenos
- samostatný DATA disk na NODE je doporučený produkční model

## Poznámky k provozu

DSM je orchestrace infrastruktury a při migraci provádí destruktivní operace až po explicitním potvrzení. Přesto před změnami storage, sítí a produkčních stacků udržuj nezávislou zálohu kritických dat.

## Hlavní změny od 1.x

- kompletní provisioning V2
- více lokalit a standardizovaný addressing
- WireGuard management fabric
- role infrastruktury
- automatizovaný NODE storage model
- Capacity Agent a dashboard
- Server Readiness
- přímý LAN/WireGuard volume transport
- lokální snapshoty bez DSM datové proxy
- live MB progress a progress bary
- Traefik/DNS cutover
- first-run setup, uživatelé a oprávnění
- self-update
- rozšířená rollback logika

Tento release je zamýšlen jako nový stabilní základ pro další vývoj DockerStackMoveru.
