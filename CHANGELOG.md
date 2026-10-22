# Zmiany

## 6.0

- Portal publiczny z linkami do sześciu pułapek: router, kamera, NAS, admin, WordPress i API.
- Fikcyjne przynęty konfiguracji, Git i kopii zapasowych; zapis źródła formularza.
- Profil bota, User-Agent, sekwencje wizyt, odstępy i wyjaśnione etykiety skanowania.
- Reguły obserwacji zarządzane w panelu, bez wykonywania kodu i restartów.
- Rzeczywiste testy HTTP Gatus/Frog, statusu Tailscale i odczytu logów Endlessh.
- Lokalna mapa Natural Earth, wybór dnia, grupowanie i odtwarzanie godzin.
- Publiczny tryb demo z fikcyjnymi danymi, bez odczytu baz produkcyjnych.
- Dokumentacja Linux/systemd i rozróżnienie przenośnej aplikacji od skryptów Alpine/OpenRC.
- 47 testów oraz wizualne sprawdzenie strony głównej i odtwarzania mapy.

## 5.2

- Statystyki loginów, haseł i kombinacji z zachowanych formularzy.
- Heurystyczne grupowanie podobnych prób logowania i ścieżek z różnych IP.
- Dzienny raport Discord za poprzedni dzień, bez loginów i haseł.
- Usuwanie wybranych lub wszystkich formularzy przez chronione POST z tokenem i potwierdzeniem.
- Dokumentacja polska i angielska oraz 33 testy.

## 5.1

- Zapisywanie loginów i haseł z formularza pułapki routera.
- Chroniony widok `/credentials`, osobna baza `600`, retencja 7 dni / 10 000 wpisów.
- Dane formularzy pomijane w backupach telemetrii, logach HTTP i Discordzie.
- Limity rozmiaru i czasu odczytu formularza oraz bezpieczne wyświetlanie HTML.
- 24 testy, w tym testy przechwycenia, wyłączenia zbierania, retencji i kontroli dostępu.

## 5.0

- Konfiguracja JSON z walidacją i zachowaniem ustawień przy aktualizacji.
- Filtrowanie, sortowanie i CSV historii Endlessh oraz podsumowanie IP.
- Wspólna aktywność HTTP, Endlessh i nieudanych logowań sshd/Dropbear.
- Wykres godzinowy i odświeżanie w tle z ochroną edytowanego formularza.
- Trwałe alerty z wyciszeniem, powrotem do normy i wykrywaniem wzrostu ruchu.
- Trwałe XP i odznaki za obserwacje SSH.
- Retencja, automatyczny backup SQLite i konfiguracja logrotate.
- Instalator Alpine/OpenRC od zera oraz generator pojedynczego aktualizatora.
- 18 testów, w tym HTTP, konfiguracja, filtry, backup i stan alertów.
