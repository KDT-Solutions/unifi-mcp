# unifi-mcp

MCP-Server, über den Claude die UniFi-Umgebungen (Gateway/Firewall, Switches, WLAN) mehrerer Kunden und eigener Standorte überwacht und gezielt verwaltet. Standard ist **nur lesen**. Schreibende Aktionen sind pro Konsole freizuschalten und immer zu bestätigen.

Läuft ausschliesslich als Docker-Container (Portainer-Git-Stack) mit Streamable-HTTP-Transport hinter Nginx Proxy Manager und wird als Custom Connector genutzt. Kein stdio, kein lokaler Betrieb.

Repository und Image sind **privat**, weil Code und Konfiguration Rückschlüsse auf Kundennetze zulassen. Trotzdem enthalten Code, README, Beispiele und Tests keine echten Daten, nur Platzhalter (`unifi.example.com`, `192.0.2.0/24`, `Kunde A`). Die Konsolen-Liste liegt nicht im Repository.

## Architektur

```
Claude ──HTTPS──> Nginx Proxy Manager ──HTTP──> unifi-mcp (Container)
                  https://mcp.example.com/unifi      │
                                                     ├── Site Manager API      https://api.ui.com/v1           (alle Konsolen, Status, ISP-Metriken)
                                                     ├── Network Integration API
                                                     │     cloud:  https://api.ui.com/v1/connector/consoles/{id}/proxy/network/integration
                                                     │     direct: https://{konsole}/proxy/network/integration
                                                     └── Legacy-API (optional, nur direct)  https://{konsole}/proxy/network/api/s/{site}/...
```

| Datei | Inhalt |
|---|---|
| `unifi_mcp/server.py` | HTTP-Transport, Bearer-Auth, Rate-Limit, Start |
| `unifi_mcp/app.py` | MCPServer-Instanz, Tool-Registrierung mit Protokollierung, Laufzeitzustand |
| `unifi_mcp/config.py` | Umgebungsvariablen, Konsolen-Datei und deren Prüfung |
| `unifi_mcp/clients.py` | Clients für Site Manager, Network Integration API (cloud/direct) und Legacy-API |
| `unifi_mcp/transport.py` | TLS mit Zertifikats-Pinning, Wiederholung bei HTTP 429, Cache, Fehlermeldungen |
| `unifi_mcp/tools_read.py` | lesende Tools |
| `unifi_mcp/tools_write.py` | einfache schreibende Aktionen |
| `unifi_mcp/tools_plan.py` | `prepare_change`, `execute_plan`, `rollback_change` |
| `unifi_mcp/store.py` | SQLite (Audit-Log, Pläne, Schreibrechte) und JSON-Sicherungen im Volume |
| `unifi_mcp/redact.py` | Maskierung von Passphrasen/Secrets, Bereinigung von API-Texten |
| `unifi_mcp/resolve.py` | Sites, Geräte, Clients über ID, Name, MAC oder IP finden |

Python 3.12, `mcp` 2.3 (MCPServer), `httpx`. Kein `pyproject.toml`: Abhängigkeiten gepinnt in `requirements.txt`, Start per `python -m unifi_mcp`.

### Verwendete UniFi-APIs

Die Endpunkte stammen aus der offiziellen Dokumentation unter https://developer.ui.com (OpenAPI-Spezifikationen *Site Manager API 1.0.0* und *UniFi Network API 11.0.97*).

**Site Manager API** (`https://api.ui.com`, Header `X-API-Key`): `GET /v1/hosts`, `GET /v1/devices`, `GET /v1/sites`, `GET /v1/isp-metrics/{5m|1h}`. Funktioniert auch für Konsolen ohne direkte Erreichbarkeit (CGNAT, dynamische IP). Rate-Limit laut Doku: 10'000 Requests/Minute für v1, 100/Minute für Early-Access-Endpunkte.

**Network Integration API** pro Konsole: Sites, Geräte (inkl. Statistiken, Ports, Funkmodule), Clients, Netze, WLANs, Firewall-Policies und -Zonen, VPN-Server und Site-to-Site-Tunnel, WAN-Schnittstellen, Hotspot-Voucher sowie die Aktionen `RESTART` (Gerät), `POWER_CYCLE` (PoE-Port). Listen sind mit `offset`/`limit` (max. 200) paginiert und mit `filter` filterbar.

Die Integration API ist laut Doku **über den Cloud-Connector der Site Manager API** erreichbar (`/v1/connector/consoles/{consoleId}/proxy/network/integration/...`, Konsolen-Firmware ab 5.0.3). Dieser Weg (`mode: cloud`) ist bevorzugt, dann muss keine Konsole öffentlich erreichbar sein. Laut Doku gilt dabei:

- Authentifizierung mit dem **Site-Manager-API-Key**. Ein Key eines einzelnen Kontos erreicht nur die Konsolen dieses Kontos, ein Organisations-Key alle Konsolen der Organisation.
- 100 Requests pro Minute und Konsole, 25 s Timeout und 10 MB Antwortgrösse pro Request.

`mode: direct` spricht die Konsole direkt an (`https://{konsole}/proxy/network/integration`) mit einem API-Key, der in der Network-App der Konsole erstellt wird.

**Legacy-API** (Benutzername/Passwort, Session-Cookie, `X-CSRF-Token`): nur als Fallback für Funktionen, die die offizielle API nicht bietet, nur pro Konsole mit `legacy_enabled: true` und nur direkt zur Konsole (`base_url`). Diese API ist von Ubiquiti **nicht offiziell dokumentiert**; die verwendeten Pfade entsprechen den verbreiteten Community-Clients und sind noch nicht gegen eine echte Konsole getestet:

| Funktion | Legacy-Pfad unter `/proxy/network/api/s/{site}/` |
|---|---|
| Client sperren/entsperren/trennen | `POST cmd/stamgr` mit `block-sta`, `unblock-sta`, `kick-sta` |
| Firmware-Update eines Geräts | `POST cmd/devmgr` mit `upgrade` |
| Signal, SSID, Switch-Port, Datenvolumen der Clients | `GET stat/sta` |
| PoE-Verbrauch, Port-Fehler, Kanalauslastung | `GET stat/device/{mac}` |
| Ereignisse, Alarme | `POST stat/event`, `GET list/alarm` |
| Portweiterleitungen | `GET list/portforward`, `POST/PUT rest/portforward` |

Anmeldung: `POST /api/auth/login`. Bei HTTP 401 (Sitzung abgelaufen) wird genau einmal neu angemeldet.

## Konfiguration

### Konsolen-Datei

JSON-Datei, per Volume read-only nach `/config/consoles.json` eingebunden (Pfad auf dem Host: Stack-Variable `CONSOLES_FILE_HOST`). Aufbau wie `config/consoles.example.json`:

```json
{
  "consoles": [
    {"name": "Kunde A", "console_id": "0000...0000:1000000001", "mode": "cloud"},
    {"name": "Kunde B", "console_id": "0000...0000:1000000002", "mode": "direct",
     "base_url": "https://unifi.example.com", "api_key_env": "UNIFI_KEY_KUNDE_B",
     "tls_fingerprint": "sha256:00:11:...:FF", "writes_enabled": false}
  ]
}
```

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `name` | ja | Anzeigename, z.B. Kundenname; eindeutig. Tools akzeptieren `name` oder `console_id` |
| `console_id` | bei `cloud` | Host-ID aus der Site Manager API (`GET /v1/hosts`). Auch bei `direct` empfohlen: dann liefert Site Manager Status, Firmware-Updates und ISP-Metriken |
| `mode` | nein | `cloud` (Standard) oder `direct` |
| `base_url` | bei `direct` und Legacy | `https://host[:port]` der Konsole, ohne Pfad |
| `api_key_env` | bei `direct` | **Name** der Variable mit dem Integration-API-Key. Bei `cloud` optional: Name einer Variable mit einem anderen Site-Manager-Key (z.B. eines anderen UI-Kontos); ohne Angabe gilt `SITE_MANAGER_API_KEY` |
| `tls_fingerprint` | nein | SHA-256 des Zertifikats der Konsole bei selbstsigniertem Zertifikat (`sha256:AA:BB:...`, mit oder ohne Doppelpunkte) |
| `writes_enabled` | nein | Standard `false` |
| `legacy_enabled` | nein | Standard `false` |
| `legacy_username_env`, `legacy_password_env` | bei Legacy | **Namen** der Variablen mit Benutzer und Passwort des lokalen Legacy-Benutzers |

Unbekannte Felder, doppelte Namen und ungültige Werte führen zum Abbruch beim Start, damit Tippfehler nicht unbemerkt bleiben. Der Key selbst steht nie in der Datei.

Fingerabdruck ermitteln (auf einem Rechner im Netz der Konsole, Ergebnis mit dem Zertifikat auf der Konsole abgleichen):

```bash
openssl s_client -connect 192.0.2.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

### Umgebungsvariablen (Portainer-Stack)

| Variable | Pflicht | Standard | Bedeutung |
|---|---|---|---|
| `MCP_API_KEY` | ja | - | Bearer-Token für den Connector (z.B. `openssl rand -hex 32`). Ohne startet der Server nicht |
| `SITE_MANAGER_API_KEY` | ja | - | Key aus unifi.ui.com, *Settings → API Keys* |
| `UNIFI_CONSOLE_SECRETS` | bei direct/Legacy | - | Secrets aller Konsolen als ein JSON-Objekt, z.B. `{"UNIFI_KEY_KUNDE_B":"...","UNIFI_LEGACY_PASSWORD_KUNDE_B":"..."}`. Die Namen sind die Werte von `api_key_env`, `legacy_username_env`, `legacy_password_env`. Alternativ einzelne Umgebungsvariablen gleichen Namens (haben Vorrang) |
| `CONSOLES_FILE_HOST` | ja | `/srv/unifi-mcp/consoles.json` | Pfad der Konsolen-Datei auf dem Docker-Host |
| `MCP_PATH` | nein | `/unifi` | Pfad des MCP-Endpunkts |
| `MCP_BIND_ADDR` / `MCP_HOST_PORT` | nein | `0.0.0.0` / `8439` | Host-Bindung |
| `CACHE_TTL_SECONDS` | nein | `30` | Cache für lesende Aufrufe; ISP-Metriken 60 s; Schreibaktionen leeren den Cache der Konsole |
| `AUDIT_RETENTION_DAYS` | nein | `365` | Aufbewahrung des Audit-Logs, `0` = unbegrenzt |
| `MCP_RATE_LIMIT_PER_MINUTE` | nein | `120` | Requests pro Minute mit gültigem Token |
| `MCP_AUTH_FAIL_LIMIT_PER_MINUTE` | nein | `10` | Fehlgeschlagene Anmeldungen pro Minute und Quelle |
| `LOG_LEVEL` | nein | `INFO` | |

Secrets nur über die Stack-Variablen, nie im Image oder Repository. Vorlage: `.env.example`.

### API-Keys und Benutzer

- Site-Manager-Key unter unifi.ui.com erstellen. Für Kundenkonsolen in einer UI-Organisation einen Organisations-Key verwenden, sonst erreicht der Connector nur die Konsolen des Key-Besitzers.
- Integration-Keys (`direct`) in der Network-App der jeweiligen Konsole erstellen. Wo die Konsole Rechte auswählen lässt, für Konsolen ohne `writes_enabled` nur lesende Rechte vergeben.
- Legacy: eigenen lokalen Benutzer der Konsole mit minimalen Rechten anlegen (für reine Lesefunktionen nur lesend; für Sperren/Trennen/Update/Portweiterleitungen sind entsprechende Admin-Rechte nötig). Kein UI-Cloud-Konto verwenden, keine Zwei-Faktor-Anmeldung möglich.

## Tools

Parameter `console` = Name oder `console_id`, `site` = Site-ID, interner Name (`default`) oder Anzeigename; ohne `site` gilt die einzige Site der Konsole. Geräte und Clients lassen sich über ID, Name, MAC oder IP angeben.

### Lesend

| Tool | Beschreibung |
|---|---|
| `get_version` | Version, Commit-Hash und Build-Zeit |
| `list_consoles` | Alle Konsolen mit Status (online/offline), Modell, Firmware, Update, Modus, Schreibrechte, Legacy |
| `list_sites(console)` | Sites, optional einer Konsole |
| `site_health(console, site)` | Ohne `console`: Übersicht aller Konsolen aus der Site Manager API. Mit `console`: WAN-Verfügbarkeit, ISP, Gateway, Geräte online/offline, Clients (gesamt/kabel/WLAN), kritische Meldungen, offene Alarme (Legacy) |
| `list_devices(console, site, type, include_stats)` | Typ, Modell, IP, MAC, Status, Firmware, Update verfügbar (inkl. Zielversion), Uptime; optional CPU/RAM |
| `device_info(console, device, site)` | Details, Ports (Link, Geschwindigkeit, PoE), Funkmodule (Band, Kanal, Breite, Sendeleistung, Wiederholungsrate). PoE-Verbrauch, Port-Fehler, Kanalauslastung mit Legacy |
| `list_clients(console, site, connection, search, limit)` | Filter wired/wireless/vpn, Suche nach MAC, IP, Name/Hostname; verbundener AP/Switch. Signal, SSID, Port, Datenvolumen mit Legacy |
| `client_info(console, client, site)` | Details eines Clients |
| `list_networks(console, site)` | Netze/VLANs, Subnetz, Gateway-IP, DHCP-Bereich, Lease, DNS, Isolation |
| `list_wlans(console, site, show_passphrase)` | SSIDs, Sicherheitsmodus, Netz, Bänder. Passwörter maskiert, Klartext nur mit `show_passphrase=true` (wird auditiert) |
| `list_firewall_rules(console, site, include_predefined)` | Firewall-Policies mit Zonen und Filtern, Firewall-Zonen; Portweiterleitungen mit Legacy |
| `list_vpn(console, site)` | VPN-Server und Site-to-Site-Tunnel (Typ, aktiviert). Einen Verbindungsstatus liefert die offizielle API nicht |
| `wan_status(console, site, period)` | WAN-Schnittstellen, gemeldete IP der Konsole, ISP, WAN-Verfügbarkeit, Internet-Probleme, ISP-Metriken (Latenz, Paketverlust, Ausfallzeit) über 24h/7d/30d |
| `list_events(console, site, hours, limit)` | Ereignisse und Alarme (Legacy); sonst Internet-Probleme und kritische Meldungen aus Site Manager |
| `firmware_overview(console)` | Alle Geräte mit verfügbarem Firmware-Update über alle Konsolen |
| `get_audit_log(console, action, hours, limit)` | Audit-Log der schreibenden Aktionen |

### Schreibend

| Tool | Weg | Beschreibung |
|---|---|---|
| `device_restart` | offizielle API | Gerät neu starten |
| `port_power_cycle` | offizielle API | PoE-Port neu starten (nur Ports mit PoE) |
| `client_block` / `client_unblock` | Legacy | Client sperren/entsperren |
| `client_reconnect` | Legacy | WLAN-Client trennen |
| `wlan_set_enabled` | offizielle API | SSID ein/aus (sendet das vollständige WLAN-Objekt mit geändertem `enabled`) |
| `create_guest_voucher` | offizielle API | Hotspot-Voucher: Dauer, Anzahl, Nutzungen, optional Datenlimit und Bandbreite |
| `device_upgrade` | Legacy | Firmware-Update eines Geräts, nur wenn die API ein Update meldet |
| `set_console_writes` | lokal | Schreibrechte einer Konsole ein/aus |
| `prepare_change` | je nach Art | Plan mit Vorher/Nachher-Diff und Plan-ID, ändert nichts |
| `execute_plan` | je nach Art | Plan ausführen |
| `rollback_change` | je nach Art | Ausgeführten Plan zurücknehmen |

`prepare_change(console, kind, changes, target, site)`:

| `kind` | API | `changes` |
|---|---|---|
| `firewall_policy.create` | offiziell | vollständige Policy im API-Format (`name`, `enabled`, `action`, `source`, `destination`, `ipProtocolScope`, `loggingEnabled`, ...) |
| `firewall_policy.update` | offiziell | nur die zu ändernden Felder |
| `network.create` | offiziell | Netz/VLAN (`name`, `management`, `enabled`, `vlanId` 2-4009, `ipv4Configuration`, ...). VLAN-ID und Name werden auf Konflikte geprüft |
| `network.update` | offiziell | nur die zu ändernden Felder |
| `wlan.update` | offiziell | nur die zu ändernden Felder (ohne Passphrase) |
| `wlan.set_passphrase` | offiziell | `{"passphrase": "..."}`, 8-63 Zeichen, nur WPA2/WPA3 Personal |
| `port_forward.create` / `port_forward.update` | Legacy | Portweiterleitung (`name`, `enabled`, `proto`, `src`, `dst_port`, `fwd`, `fwd_port`, ...) |

Bei `*.update` wird der aktuelle Stand gelesen und mit `changes` zusammengeführt (Objekte rekursiv, Listen ersetzt). Nicht änderbar: `id`, `metadata`, `default`, `index`. Löschen ist nicht vorgesehen.

## Sicherheitsmodell

- **Standard nur lesen.** Schreibende Tools prüfen zuerst `writes_enabled` der Konsole (Konsolen-Datei, übersteuerbar mit `set_console_writes`, gespeichert im Volume). Ist es aus, gibt es eine klare Fehlermeldung, auch ohne `confirm`.
- **`confirm=true` zwingend**, als echter Boolean (`"true"` oder `1` werden abgelehnt). Ohne `confirm` liefern die Tools eine Vorschau mit dem aufgelösten Ziel und ändern nichts.
- **Pläne für heikle Änderungen.** `prepare_change` ändert nichts und zeigt ein Diff; Passwörter erscheinen darin nur als `***`. Pläne verfallen nach 15 Minuten, sind an die Konsole gebunden und werden genau einmal atomar verbraucht. `execute_plan` bricht ab, wenn sich der Stand seit der Planung geändert hat.
- **Sicherung vor jeder Ausführung** als JSON in `/data/backups/<plan_id>.json` (Rechte 0600). `rollback_change` stellt den Stand wieder her bzw. löscht ein neu angelegtes Objekt. Die Sicherungen enthalten den vollständigen vorherigen Stand, bei WLANs also auch die alte Passphrase: das Volume entsprechend schützen. Die neue Passphrase wird nach der Ausführung aus dem Plan-Speicher entfernt.
- **Audit-Log** in `/data/state.db`: Zeitpunkt, Konsole, Aktion, Ziel, Ergebnis (`succeeded`, `failed`, `unknown_verify_state`, `planned`, `aborted_changed`), auch für `show_passphrase` und `set_console_writes`. Abruf mit `get_audit_log`. Zusätzlich jede Tool-Ausführung als JSON-Zeile auf stdout (Parameter ohne Secrets).
- **Unklarer Zustand:** Läuft ein Schreibvorgang in einen Timeout oder bricht die Verbindung ab, meldet das Tool das ausdrücklich. Es wird nie automatisch wiederholt; zuerst den Ist-Zustand lesen. HTTP 429 (nicht ausgeführt) wird nach `Retry-After` höchstens dreimal wiederholt.
- **Keine Secrets in Ausgaben und Logs.** Passphrasen, Passwörter, Shared Secrets und Schlüssel werden maskiert. Bekannte Secret-Werte (alle Keys und Tokens aus der Umgebung) werden zusätzlich aus allen Fehlermeldungen entfernt. Fehlermeldungen enthalten nur Statuscode und Fehlercode der API.
- **TLS immer geprüft.** Bei selbstsigniertem Zertifikat wird mit `tls_fingerprint` gepinnt: Der Dienst holt das Zertifikat, vergleicht den SHA-256-Fingerabdruck und baut danach nur Verbindungen auf, die genau diesem Zertifikat vertrauen. Ein anderes Zertifikat scheitert beim TLS-Handshake, bevor der API-Key gesendet wird. Eine Option zum Abschalten der Prüfung gibt es nicht.
- **Rate-Limit auf den MCP-Endpunkt:** begrenzt Requests mit gültigem Token (Schutz bei geleaktem Token) und fehlgeschlagene Anmeldungen.
- **Bearer-Auth** mit Konstantzeit-Vergleich, auch für `/healthz`. Kein OAuth.
- **API-Daten sind Daten:** Geräte-, Host-, SSID-Namen und Notizen können beliebigen Text enthalten. Steuerzeichen und Richtungszeichen werden entfernt, lange Texte gekürzt; die Server-Instruktionen weisen das Modell darauf hin.
- **Container:** Nicht-Root (UID 10001), read-only Root-Dateisystem, keine Capabilities.

Die Bestätigung ist ein Tool-Parameter und keine unabhängige menschliche Freigabe: ein Client mit Token kann sie selbst setzen.

## Deployment (Portainer-Git-Stack)

1. Image: GitHub Actions (`.github/workflows/docker-publish.yml`) führt bei jedem Push die Tests aus. Steht in `VERSION` eine Version, zu der es noch keinen Tag gibt, setzt der Workflow beim Push auf `main` den Tag `vX.Y.Z` und baut `ghcr.io/kdt-solutions/unifi-mcp:X.Y.Z` und `:latest` mit den Build-Args `APP_VERSION`, `GIT_SHA`, `BUILD_TIME`. Manueller Lauf: nur `:dev-<Commit>`.
2. Portainer *Registries*: ghcr.io-Eintrag mit einem GitHub-Token (Scope `read:packages`), da das Package privat ist.
3. Konsolen-Datei auf dem Docker-Host ablegen (z.B. `/srv/unifi-mcp/consoles.json`, lesbar für UID 10001).
4. Portainer *Stacks → Add stack → Repository*: Repository `https://github.com/KDT-Solutions/unifi-mcp`, Referenz `refs/heads/main`, Compose-Pfad `docker-compose.yml`, Authentifizierung mit einem GitHub-Token (privates Repository). **GitOps-Updates aus** (kein Polling, kein Webhook). Den Stack als Administrator anlegen, da er einen Bind-Mount für die Konsolen-Datei nutzt.
5. Stack-Variablen setzen (siehe oben und `.env.example`), mindestens `MCP_API_KEY`, `SITE_MANAGER_API_KEY`, `CONSOLES_FILE_HOST`, bei Bedarf `UNIFI_CONSOLE_SECRETS`.
6. Nginx Proxy Manager: Proxy-Host `mcp.example.com` → `http://<Docker-Host>:8439`, Let's-Encrypt-Zertifikat, Force SSL. Der Pfad `/unifi` wird unverändert durchgereicht; Authorization-Header nicht entfernen.
7. Prüfen: `curl -i https://mcp.example.com/healthz` liefert `401`, mit `-H "Authorization: Bearer <MCP_API_KEY>"` liefert es `200`.

Updates: neue Version in `VERSION` pushen, dann in Portainer den Stack mit *Pull and redeploy* aktualisieren. Konsolen-Datei geändert: Stack neu starten.

## Als Connector hinzufügen

- URL: `https://mcp.example.com/unifi`
- Authentifizierung: keine Anmeldung (kein OAuth), Header `Authorization: Bearer <MCP_API_KEY>`
- Danach `get_version` aufrufen und Version/Commit prüfen.

## Tests und Abnahme

```bash
pip install -r requirements-dev.txt
pytest -q
```

Unit-Tests mit gemockten API-Antworten (Platzhalterdaten): Konfigurationsprüfung, Bearer-Auth und Rate-Limit, Cloud-Connector- und Direkt-URLs mit den richtigen Keys, Paginierung, 429-Backoff, Cache, alle lesenden Tools, Maskierung und Audit von Passphrasen, Schreibrechte, `confirm`-Logik, Legacy-Login mit CSRF und Neuanmeldung, Pläne (Diff, Ablauf, Einmaligkeit, geänderter Stand, Sicherung, Rollback), TLS-Pinning gegen einen lokalen HTTPS-Server.

Abnahme gegen echte Konsolen (noch offen):

1. Nur lesend gegen eine einzelne Konsole: `list_consoles`, `site_health`, `list_devices`, `list_clients`.
2. Eine Konsole mit `writes_enabled=true`: `device_restart` an einem unkritischen Gerät, `prepare_change` ohne Ausführung.

## Release

```bash
echo 0.1.1 > VERSION
git commit -am "Release 0.1.1" && git push
```
