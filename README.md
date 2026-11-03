<div align="center">

# 🛡️ USB Guard

**Ochrona stacji roboczej Windows przed nieautoryzowanymi nośnikami USB**

![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%202004%2B%20%7C%2011-0078D6?logo=windows&logoColor=white)
![Version](https://img.shields.io/badge/wersja-1.5.2-2ea44f)
![Admin](https://img.shields.io/badge/wymaga-administratora-critical)

Skrypt PowerShell typu **fail-closed**, który wykorzystuje wbudowane zasady instalacji urządzeń, białą listę instancji oraz mechanizmy audytu i raportowania.

</div>

---

## Spis treści

- [Funkcje](#funkcje)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Użycie](#użycie)
- [Bezpieczeństwo](#bezpieczeństwo)
- [Pliki i ślady w systemie](#pliki-i-ślady-w-systemie)
- [Identyfikatory zdarzeń Windows](#identyfikatory-zdarzen-windows)

---

## Funkcje

- 🔒 Blokada nowych nośników USB na poziomie instalacji sterownika
- 📋 Biała lista oparta na pełnym identyfikatorze instancji (VID + PID + numer seryjny), która odróżnia dwa egzemplarze tego samego modelu
- 🧾 Kontrola integralności białej listy (skrót SHA-256 w rejestrze)
- 🔍 Kontrola spójności białej listy z zasadami w rejestrze (wykrywa ręcznie dopisane wyjątki i wyłączoną blokadę)
- ⚡ Automatyczne rejestrowanie prób podłączenia (audyt 6416/6423 + zadanie Harmonogramu na koncie SYSTEM)
- 📝 Zapis zdarzeń w trzech miejscach: log tekstowy, Dziennik zdarzeń Windows, miesięczny CSV
- 📊 Miesięczny raport bezpieczeństwa HTML + CSV
- ♻️ Pełna, odwracalna deinstalacja

> [!NOTE]
> Blokowane są tylko nośniki pamięci masowej. Klawiatury, myszy, kamery, drukarki i inne urządzenia USB działają normalnie.

## Wymagania

| Wymaganie | Szczegóły |
|---|---|
| System | Windows 10 **2004+** lub Windows 11 (obsługa `AllowDenyLayered`) |
| PowerShell | Windows PowerShell **5.1** |
| Uprawnienia | Administrator |
| Narzędzia systemowe | `pnputil.exe` (`/remove-device`, `/scan-devices`), `auditpol.exe` |

## Instalacja

Uruchom PowerShell **jako administrator!**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\USB_GUARD_1_5_2.ps1 Install
```

Instalacja:

1. kopiuje skrypt do `C:\Program Files\USBGuard` i dodaje katalog do `PATH`,
2. dodaje skrót `USBG` do profilu PowerShell,
3. włącza blokadę i audyt PnP,
4. rejestruje zadanie `\USBGuard\USBGuard-Scan`,
5. uruchamia `Purge`, który trzeba potwierdzić słowem **`TAK`**.

Po instalacji otwórz **nowe** okno PowerShell jako administrator, żeby wczytał się skrót `USBG`.

> [!WARNING]
> `Purge` usuwa z systemu wszystkie **niepodłączone** nośniki USB, które były wcześniej używane. Po instalacji każdy nośnik trzeba dodać do białej listy, inaczej nie zadziała.

## Użycie

```text
USBG <Akcja> [opcje]
```

| Akcja | Opis | Parametry |
|---|---|---|
| `Install` | instaluje program i włącza blokadę | — |
| `Uninstall` | wyłącza ochronę i usuwa program (potwierdzenie `TAK`) | — |
| `Status` | stan blokady, spójność, podłączone nośniki | — |
| `List` | wyświetla białą listę | — |
| `Add` | dodaje nośnik do białej listy | `-InstanceId`, `-Description`, `-Owner` |
| `Remove` | usuwa nośnik z białej listy (od razu go odłącza) | `-InstanceId` |
| `Purge` | czyści białą listę i usuwa niepodłączone nośniki | — |
| `Report` | tworzy raport miesięczny HTML + CSV | `-Month RRRR-MM` |
| `Scan` | rejestruje próby podłączenia (uruchamiany automatycznie) | — |
| `Help` | pomoc ogólna lub dla wybranej akcji | `<akcja>` |

### Przykłady

```powershell
# Stan ochrony
USBG Status

# Autoryzacja podłączonego pendrive'a (skrypt wyświetli listę do wyboru)
USBG Add -Description "Pendrive Kadry" -Owner "Jan Kowalski"

# Autoryzacja nośnika bez podłączania
USBG Add -InstanceId "USB\VID_0781&PID_5567\4C530001231122117401" -Description "Dysk zapasowy"

# Odebranie autoryzacji
USBG Remove -InstanceId "USB\VID_13FE&PID_4200\123456"

# Raport za październik 2026
USBG Report -Month 2026-10

# Pomoc dla akcji
USBG Help Add
```

<!-- Zrzuty ekranu: umieść pliki w folderze docs/ i odkomentuj
<p align="center">
  <img src="docs/status.png" width="700" alt="USBG Status">
  <img src="docs/report.png" width="700" alt="Raport miesięczny">
</p>
-->

## Bezpieczeństwo

| Mechanizm | Opis |
|---|---|
| **Integralność listy** | Po każdym zapisie SHA-256 pliku trafia do `HKLM\SOFTWARE\USBGuard`. Ręczna zmiana pliku → zdarzenie 3100, zasady nie są zmieniane. |
| **Spójność zasad** | Biała lista porównywana z `AllowInstanceIDs` + kontrola zakazu `USB\Class_08` → zdarzenie 3101 przy rozbieżności. |
| **ACL** | Katalog danych dostępny tylko dla SYSTEM i Administratorów. |
| **Zapis atomowy** | Zapis do `.tmp`, potem przeniesienie na miejsce docelowe. |
| **Mutex** | `Global\USBGuard` chroni przed równoczesnym zapisem przez administratora i zadanie harmonogramu. |
| **Bezpieczny eksport** | Ochrona przed CSV injection i kodowanie HTML w raportach. |
| **Walidacja wejścia** | `ValidateSet` dla akcji, `ValidatePattern` dla formatu miesiąca. |
| **Tryb ścisły** | `Set-StrictMode -Version 2.0` i `$ErrorActionPreference = 'Stop'`. |

Po komunikacie o naruszeniu integralności lub spójności:

```powershell
USBG Purge
USBG Add -Description "..."   # ponowne dodanie zaufanych nośników
```

## Pliki i ślady w systemie

| Element | Lokalizacja |
|---|---|
| Program | `C:\Program Files\USBGuard\USB_Guard.ps1` |
| Biała lista | `C:\ProgramData\USBGuard\whitelist.json` |
| Logi | `C:\ProgramData\USBGuard\Logs\USBGuard_RRRR-MM.log`, `events_RRRR-MM.csv` |
| Raporty | `C:\ProgramData\USBGuard\Reports\USBGuard_Report_<KOMPUTER>_<RRRR-MM>.*` |
| Stan | `HKLM\SOFTWARE\USBGuard` |
| Zasady | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` |
| Zadanie | `\USBGuard\USBGuard-Scan` |
| Dziennik zdarzeń | `Application`, źródło `USBGuard` |

<details>
<summary>Przykładowy <code>whitelist.json</code></summary>

```json
{
  "Version": 1,
  "Updated": "2026-11-01T23:25:29",
  "Devices": [
    {
      "InstanceId": "USB\\VID_0781&PID_55A9\\04019E79A8...",
      "VendorId": "0781",
      "ProductId": "55A9",
      "Serial": "04019E79A8...",
      "HasUniqueSerial": true,
      "Name": "SanDisk 3.2Gen1",
      "Description": "SanDisk Testowy",
      "Owner": "",
      "AddedBy": "WIN11EY\\ey",
      "AddedOn": "2026-11-01T23:25:29"
    }
  ]
}
```

</details>

## Identyfikatory zdarzen Windows

| ID | Nazwa | Poziom | Znaczenie |
|---|---|---|---|
| 1001 | `TrustedConnected` | ℹ️ Informacja | podłączono nośnik z białej listy |
| 1100 | `ReportGenerated` | ℹ️ Informacja | wygenerowano raport |
| 1200 | `WhitelistChanged` | ℹ️ Informacja | zmieniono białą listę |
| 1201 | `PolicySynced` | ℹ️ Informacja | zsynchronizowano zasady |
| 1202 | `PurgeCompleted` | ℹ️ Informacja | wykonano Purge |
| 2001 | `Blocked` | ⚠️ Ostrzeżenie | zablokowano nieautoryzowany nośnik |
| 3001 | `UntrustedActive` | ❌ Błąd | nośnik spoza listy działa (blokada nie zadziałała) |
| 3100 | `ConsistencyError` | ❌ Błąd | plik białej listy zmieniony poza USB Guard |
| 3101 | `PolicyDrift` | ❌ Błąd | zasady różnią się od białej listy |
| 3900 | `InternalError` | ❌ Błąd | nieobsłużony wyjątek |

---
