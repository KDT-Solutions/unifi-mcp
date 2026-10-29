"""Gemeinsame Fehlerklassen. Meldungen sind für den Client bestimmt und
enthalten nie Header, API-Keys, Passwörter oder Passphrasen."""


class UnifiError(Exception):
    """Basisklasse für erwartete Fehler mit Klartext-Meldung."""


class ConfigError(UnifiError):
    """Konsolen-Konfiguration ungültig oder unvollständig."""


class ApiError(UnifiError):
    """Fehlerantwort einer UniFi-API (nur Statuscode und Fehlercode, nie Inhalte mit Secrets)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class GuardError(UnifiError):
    """Aktion durch Schutzregeln blockiert oder Eingabe unzulässig."""


class UnclearStateError(UnifiError):
    """Timeout oder Abbruch während eines Schreibvorgangs: Ob die Aktion ausgeführt wurde, ist unbekannt."""
