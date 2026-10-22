# 🐸 Frog SOC — monitoring VPS i pułapki na boty

Frog SOC to lekki panel do domowego laboratorium cyberbezpieczeństwa na
**Alpine Linux z OpenRC**. Łączy monitoring serwera, prosty honeypot HTTP,
historię połączeń osobnego honeypota SSH **Endlessh** oraz alerty Discord.
Aplikacja używa wyłącznie biblioteki standardowej Pythona — nie wymaga pip,
Node.js ani Dockera.

To narzędzie obserwacyjne: zbiera zdarzenia i wysyła powiadomienia.
Nie blokuje adresów IP, nie jest firewallem ani pełnym systemem SIEM.

## Co robi

- Pokazuje pamięć RAM, zajętość dysku, load i uptime serwera.
- Wyświetla lokalne porty TCP i wykrywa procesy Endlessh, Gatus oraz Tailscale.
- Udaje panel logowania routera pod `/`, `/admin`, `/login` i `/cgi-bin/luci`.
  Rejestruje czas, IP klienta, metodę HTTP i ścieżkę. Nie zapisuje formularzy,
  loginów ani haseł wprowadzanych do pułapki.
- Pokazuje najczęstsze IP, odwiedzane ścieżki, ostatnie żądania i historię HTTP.
- Importuje logi Endlessh do SQLite i pokazuje historię połączeń SSH:
  **IP, port klienta, początek, koniec i długość sesji**.
- Czyta próbki lokalnych logów sshd/Dropbear z nieudanymi logowaniami.
  Są one prezentowane oddzielnie od sesji Endlessh.
- Geolokalizuje publiczne IP z pułapki HTTP i pokazuje schemat współrzędnych.
- Może wysyłać alerty na Discord.
- Rozwija cyberżabę: zdarzenia HTTP dają XP, poziomy i odznaki.

## Architektura i zależność od Endlessh

**Porty 31888 i 41888 w tej dokumentacji są przykładami z VPS autora.**
Nie są portami wymaganymi przez projekt ani numerami przypisanymi do tych
usług. Na własnym serwerze wybierz dostępne porty przydzielone przez hosting.
W dołączonym kodzie przykładowe wartości są zapisane jako ustawienia domyślne;
przed wdrożeniem dopasuj je do swojej konfiguracji.

**Frog SOC i Endlessh to dwie osobne usługi, nasłuchujące na dwóch różnych
portach TCP. Oba porty trzeba skonfigurować na serwerze oraz udostępnić
w firewallu i ewentualnym panelu przekierowań hostingu.**

| Element | Rola | Przykładowy port w dołączonej konfiguracji |
| --- | --- | --- |
| Frog SOC | Honeypot HTTP oraz chroniony panel WWW | **31888/TCP** |
| Endlessh | Honeypot SSH, powoli wysyłający baner | **41888/TCP** |
| Prawdziwy serwer SSH | Logowanie administratora na VPS | Osobny port ustalony przez administratora/hosting |

W dołączonej konfiguracji Frog SOC uruchamia własny serwer HTTP na `0.0.0.0:31888`. Endlessh musi być
zainstalowany i uruchomiony osobno. Frog nie tworzy drugiej instancji
Endlessh: obserwuje połączenia TCP na 41888 i importuje logi istniejącej usługi.

Endlessh zatrzymuje klientów na etapie banera SSH, przed uwierzytelnieniem.
Nie jest prawdziwym serwerem logowania i nie zbiera haseł. Nie zastępuj nim
portu, którego używasz do administracji VPS.

Bez Endlessh działa panel systemowy i pułapka HTTP, ale historia Endlessh
pozostanie pusta. Bez włączonego logowania Endlessh sam nasłuch na 41888
nie wystarczy do odtworzenia historii.

## Wymagania

| Zależność | Do czego jest potrzebna |
| --- | --- |
| Alpine Linux + OpenRC | Obsługiwane środowisko skryptu aktualizacji i usług |
| Python 3 z modułem `sqlite3` | Serwer HTTP, monitoring, baza i import logów |
| Dostęp do `/proc` | Pamięć, procesy, porty i aktywne połączenia |
| Endlessh | Osobny honeypot SSH na 41888 i jego logi ACCEPT/CLOSE |
| Tailscale | Zdalny dostęp do chronionego panelu przez prywatną sieć |
| Uprawnienia root / sudo | Aktualizacja `/opt/frog-soc` i restart usług |
| Odczyt logów i zapis w `/opt/frog-soc` | Historia sesji i zdarzeń |

Gatus jest opcjonalną obserwowaną usługą. Frog nie wymaga go do uruchomienia.
Discord jest opcjonalny. Połączenie HTTPS do `ipwho.is` jest potrzebne tylko
do geolokalizacji, a do webhooka Discord — tylko do powiadomień.

## Konfiguracja portów

Najpierw ustal port publiczny i port lokalnego nasłuchu dla każdej usługi.
Jeżeli hosting wystawia port bez zmiany numeru, mogą być takie same — tak
jest w przykładzie autora. Jeśli używa mapowania NAT, numery mogą się różnić.
Nie zakładaj, że Twój hosting udostępnia numery z tego README.

| Ustawienie | Co wpisać na swoim VPS |
| --- | --- |
| Port publiczny HTTP | Port TCP dostępny/przydzielony dla pułapki Frog |
| Lokalny port Frog | Wartość `PORT` w aplikacji, zgodna z celem mapowania |
| Port publiczny Endlessh | Drugi dostępny/przydzielony port TCP dla pułapki SSH |
| Lokalny port Endlessh | Wartość `-p` usługi, zgodna z monitoringiem Frog i celem mapowania |
| Port administracyjny SSH | Osobny port prawdziwego serwera SSH |

Poniższe polecenia i adresy używają przykładowych **31888/41888**. Zastąp je
własnymi numerami; przykłady nie konfigurują portów automatycznie.

### 1. Frog SOC — przykład 31888/TCP

W kodzie aplikacji port określa `PORT = 31888`. W skrypcie
`update-frog-soc-4.sh` aplikacja jest osadzona w bloku Python; wersja gotowa
do wdrożenia znajduje się w `deploy/app.py`.

Dla publicznej pułapki HTTP dopuść ruch TCP na ten port. Na hostingu z NAT
lub przydzielonymi portami ustaw mapowanie:

```text
publiczny port HTTP → VPS:31888/TCP
```

Port publiczny może różnić się od lokalnego, ale musi prowadzić na właściwy
lokalny nasłuch. Samo uruchomienie procesu nie tworzy reguły firewall ani NAT.

Panel `/soc`, `/ssh` i pozostałe widoki administracyjne korzystają z tego
samego portu co honeypot. Kod dopuszcza je tylko z localhost lub zakresu
`100.64.0.0/10` używanego przez Tailscale, a następnie wymaga HTTP Basic Auth:
login **`frog`**, hasło z `/opt/frog-soc/.soc-password`.

Panel otwieraj przez Tailscale:

```text
http://ADRES_TAILSCALE_VPS:31888/soc
http://ADRES_TAILSCALE_VPS:31888/ssh
```

Aplikacja sama nie zapewnia HTTPS. Dostęp administracyjny prowadź przez
Tailscale lub tunel SSH. Jeśli ustawiasz reverse proxy, pamiętaj, że kontrola
źródła używa adresu połączenia TCP, a nie `X-Forwarded-For`; proxy na localhost
zmieni sposób działania tej kontroli.

### 2. Endlessh — przykład 41888/TCP

Przykład osobnej usługi OpenRC `/etc/init.d/endlessh`, zgodny z wdrożoną
konfiguracją:

```sh
#!/sbin/openrc-run
name="endlessh"
command="/usr/local/bin/endlessh"
command_args="-p 41888 -d 10000 -m 256 -v"
command_background=true
pidfile="/run/endlessh.pid"
output_log="/var/log/endlessh.log"
error_log="/var/log/endlessh.log"
depend() { need net; }
```

Dostosuj `command` do miejsca instalacji Endlessh. `-p` wybiera port,
`-d 10000` ustawia odstęp banerów na 10 sekund, `-m 256` limit klientów,
a **`-v` włącza logi wymagane przez historię**.

Po zainstalowaniu Endlessh i zapisaniu usługi, jako root:

```sh
chmod +x /etc/init.d/endlessh
rc-update add endlessh default
rc-service endlessh start
```

Dla istniejącej usługi wprowadź zmiany w jej aktualnej konfiguracji i użyj
`rc-service endlessh restart`. Restart rozłącza bieżące sesje.

Dopuść TCP 41888 w firewallu i, jeśli hosting tego wymaga, skonfiguruj:

```text
publiczny port pułapki SSH → VPS:41888/TCP
```

Upewnij się, że port nie koliduje z prawdziwym SSH ani z Frog SOC.
Przy zmianie lokalnego portu Endlessh zaktualizuj również odwołania do
`41888` w aplikacji Frog; obecnie są wpisane w kodzie, nie w zmiennej środowiska.
Zmiany źródeł synchronizuj między osadzoną aplikacją i `deploy/app.py`.

## Historia Endlessh — jak działa

1. Endlessh zapisuje `ACCEPT` przy przyjęciu klienta oraz `CLOSE` przy jego
   usunięciu. `CLOSE` zawiera `time=...` z długością sesji.
2. Frog co 5 sekund odczytuje nowe linie logów i zapisuje sesje w SQLite.
3. Panel `/ssh` prezentuje 50 sesji na stronę, od najnowszych.

Ważne szczegóły:

- Pole `port` w logu Endlessh to **port źródłowy klienta**, nie port nasłuchu.
- Długość zakończonej sesji pochodzi z Endlessh, z dokładnością do milisekund.
  Może przekraczać czas, po którym klient zamknął terminal: Endlessh musi
  jeszcze wykryć zamknięcie połączenia.
- `brak CLOSE` oznacza sesję otwartą lub niekompletne logi. Nie jest dowodem,
  że połączenie nadal trwa. Osobny licznik aktywnych TCP pochodzi z jądra.
- Jeśli zachował się tylko CLOSE, początek jest wyliczany z końca i długości.
- IPv4 może być zapisane jako adres mapowany IPv6, np. `::ffff:192.0.2.10`.
- Czasy w panelu są prezentowane w strefie czasowej serwera.
- Historia i pozycje odczytu logów przetrwają restart aplikacji.
- Obsługiwana jest rotacja przez zmianę nazwy i wykryte skrócenie pliku.
  `copytruncate` może stracić wpisy pomiędzy kopiowaniem a skróceniem.
- Importowane są dostępne logi nieskompresowane; `.gz`, `.xz`, `.bz2` są pomijane.
- Starych sesji bez zachowanych logów nie da się odtworzyć.

`deploy/app.py` czyta wyłącznie `/var/log/endlessh.log*`, zgodnie z usługą
powyżej. Wersja w `update-frog-soc-4.sh` sprawdza również
`/var/log/endlessh/*.log*`, `/var/log/messages*` i `/var/log/syslog*`.

Alternatywnie Endlessh może logować przez `-v -s` do syslog. Wtedy potrzebujesz
uruchomionego sysloga oraz importera skonfigurowanego na odpowiedni plik.
Dla klasycznego syslog bez roku importer wybiera rok najbliższy dacie
modyfikacji pliku; zmieniona data starego pliku może prowadzić do błędnego roku.

Importowane logi muszą pochodzić z **jednej instancji Endlessh na 41888**.
Przy wielu instancjach wydziel log tej właściwej i ustaw `ENDLESSH_LOGS`.
Nie importuj równocześnie stdout i syslog tej samej instancji — różna precyzja
czasu może spowodować duplikaty. Proces Frog musi mieć prawo odczytu logów;
błędy importu są pokazywane w panelu.

## Instalacja i aktualizacja

**Repozytorium zawiera aktualizację istniejącej instalacji Frog SOC 3.x/4.x,
a nie kompletny instalator od zera.** Skrypty nie instalują Pythona,
Endlessh, Tailscale ani reguł firewall/NAT.

Wymagane istniejące pliki:

```text
/opt/frog-soc/app.py
/opt/frog-soc/.soc-password
/etc/init.d/frog-soc
```

### Wariant zalecany: pakiet deploy z backupem bazy

Po sklonowaniu repozytorium skopiuj katalog `deploy` na VPS, np.:

```sh
scp -r deploy UZYTKOWNIK@VPS:~/frog-update
ssh UZYTKOWNIK@VPS
sudo sh ~/frog-update/deploy.sh
```

Jeśli administracyjne SSH ma inny port, dodaj `-P PORT_SSH` do `scp`
i `-p PORT_SSH` do `ssh`, albo użyj własnego aliasu SSH.

Skrypt:

- sprawdza składnię aplikacji;
- zapisuje kopię aplikacji i spójny backup SQLite w
  `/opt/frog-soc/backups/endlessh-DATA-CZAS/`;
- podmienia aplikację i restartuje tylko Frog SOC;
- sprawdza `/health` i autoryzowany `/ssh`, a następnie odczyt logów;
- przy błędzie restartu lub kontroli HTTP przywraca poprzednią aplikację.

Rollback automatyczny dotyczy aplikacji. Kopia bazy pozostaje do ewentualnego
ręcznego przywrócenia; nowe tabele historii nie są usuwane przy rollbacku.
Skrypt nie restartuje Endlessh i nie zmienia portów.

### Wariant pojedynczego skryptu aktualizacji

```sh
sudo sh update-frog-soc-4.sh
```

Wymaga Alpine/OpenRC i istniejącej instalacji. Zachowuje hasło oraz dane,
robi backup aplikacji, sprawdza składnię i cofa podmianę przy błędzie restartu.
Może interaktywnie zapytać o opcjonalny webhook Discord. Ten wariant nie
wykonuje osobnej kopii bazy, którą zapewnia pakiet `deploy`.

## Widoki panelu

| Ścieżka | Zawartość |
| --- | --- |
| `/soc` | Centrum monitoringu VPS i usług |
| `/stats` | Statystyki pułapki HTTP, IP i ścieżki |
| `/history` | Godzinowa historia HTTP za 48 godzin |
| `/ssh` | Historia Endlessh i osobne statystyki nieudanych logowań SSH |
| `/geo` | Schemat współrzędnych publicznych IP HTTP |
| `/investigate` | Dane do analizy: procesy, alerty i logi SSH |
| `/frog` | Poziom cyberżaby, XP i odznaki |
| `/soc/json` | Dane monitoringu w JSON |
| `/health` | Publiczna kontrola działania serwera HTTP |

Wszystkie wymienione widoki poza `/health` wymagają autoryzacji panelu.

## Dane i retencja

| Plik | Zawartość |
| --- | --- |
| `/opt/frog-soc/soc-history.sqlite3` | Zdarzenia HTTP, geolokalizacja, sesje Endlessh i kursory importu |
| `/opt/frog-soc/events.jsonl` i `.old` | Rotowane pliki zdarzeń HTTP |
| `/opt/frog-soc/.soc-password` | Hasło panelu |
| `/opt/frog-soc/.discord-webhook` | Opcjonalny adres webhooka |
| `/var/log/endlessh.log` | Log źródłowy osobnej usługi Endlessh |

HTTP w SQLite ma limit 90 dni i 30 tys. zdarzeń. Bufor w RAM przechowuje
maksymalnie 600 wpisów; część statystyk bieżących korzysta z tego bufora,
więc przy dużym ruchu nie obejmuje całej godziny.

Historia Endlessh nie ma automatycznego limitu retencji i może rosnąć.
Zaplanuj kopie bazy, kontrolę miejsca i rotację logów.

## Alerty i ograniczenia

Alerty obejmują RAM/dysk od 85%, co najmniej 100 żądań HTTP w godzinie
(w dostępnym buforze), co najmniej 50 żądań jednego IP w buforze,
niewykryte usługi i co najmniej 10 wpisów nieudanych logowań SSH w próbce logów.
Worker sprawdza stan co minutę. Wyciszenie powtórzeń wynosi 15 minut dla
identycznej treści komunikatu; zmiana liczby w treści może utworzyć nowy alert.

Wykrycie procesu Gatus/Tailscale nie potwierdza sprawności usługi ani tunelu.
Zwykłe wejście do pułapki też jest zdarzeniem — sam wpis nie dowodzi ataku.
Geolokalizacja jest orientacyjna: usługa `ipwho.is` otrzymuje publiczne IP,
a wskazany kraj nie dowodzi lokalizacji osoby. Maksymalnie wykonywanych jest
12 prób geolokalizacji na godzinę. Dane są buforowane przez 30 dni.

Nie dodawaj do Git hasła panelu, webhooka, kluczy SSH, logów ani bazy zdarzeń.

## Testy

```sh
sh -n update-frog-soc-4.sh
sh -n deploy/deploy.sh
python3 -m unittest discover -s tests -v
```

Testy sprawdzają parowanie ACCEPT/CLOSE, dokładność czasu, IPv6, równoległe
sesje, duplikaty, rotację i skrócenie logu, niepełne linie, rok w syslog,
stronicowanie oraz komunikat o braku logów.

## Pliki repozytorium

- `update-frog-soc-4.sh` — pojedynczy skrypt aktualizacji z osadzoną aplikacją.
- `deploy/app.py` — aplikacja z importem dedykowanego logu Endlessh.
- `deploy/deploy.sh` — wdrożenie z backupem aplikacji i SQLite oraz kontrolą HTTP.
- `tests/test_endlessh.py` — testy historii połączeń.

Dokumentacja upstream: [Endlessh — SSH tarpit](https://github.com/skeeto/endlessh).
