# Changelog

## 0.1.0

Erste Version.

- Lesend: `get_version`, `list_consoles`, `list_sites`, `site_health`, `list_devices`, `device_info`, `list_clients`, `client_info`, `list_networks`, `list_wlans`, `list_firewall_rules`, `list_vpn`, `wan_status`, `list_events`, `firmware_overview`, `get_audit_log`.
- Schreibend: `device_restart`, `port_power_cycle`, `client_block`, `client_unblock`, `client_reconnect`, `wlan_set_enabled`, `create_guest_voucher`, `device_upgrade`, `set_console_writes`.
- Pläne: `prepare_change`, `execute_plan`, `rollback_change` für Firewall-Policies, Netze/VLANs, WLANs, WLAN-Passwort und Portweiterleitungen.
- Site Manager API, Network Integration API über Cloud-Connector oder direkt, Legacy-API als optionaler Fallback.
- TLS-Pinning per SHA-256-Fingerabdruck, Rate-Limit auf den MCP-Endpunkt, Audit-Log und Sicherungen im Volume.
