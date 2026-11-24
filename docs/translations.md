# Translations of the admin UI

The admin UI is in English, Dutch (`nl`), French (`fr`) and German (`de`). Which language a visitor gets is
described in the [README](../README.md#admin-ui-access) (the account's choice, else the browser's language, else
English).

> **Review status: unreviewed.** The Dutch, French and German texts were written without a native speaker's review.
> They follow the glossary below, but wording, tone and terms should be checked by native speakers before a release
> that advertises them. Corrections go into the `.resx` files; nothing else needs to change.

## Where the texts are

| File | Contents |
|---|---|
| `src/Waf.Web/Resources/SharedResource.resx` | English, the source. The key of every text is the English text itself. |
| `src/Waf.Web/Resources/SharedResource.nl.resx` | Dutch |
| `src/Waf.Web/Resources/SharedResource.fr.resx` | French |
| `src/Waf.Web/Resources/SharedResource.de.resx` | German |

The translations are compiled into satellite assemblies and shipped inside the single-file packages.

## Writing texts in the code

All helpers are in `src/Waf.Web/Text.cs`; Razor files use them directly (`@T("…")`).

| Helper | Use for | Example |
|---|---|---|
| `T(text, values…)` | A text shown now. | `@T("Version {0}", version)` |
| `TM(text, values…)` | A text with markup (`<strong>`, `<em>`, `<code>`, links). The values are HTML-encoded. | `@TM("Signed in as <strong>{0}</strong>.", name)` |
| `Plural(count, one, other, values…)` | Counted things. `{0}` is the count (formatted in the language), more values from `{1}`. French uses the singular for 0. | `Plural(n, "{0} recovery code left", "{0} recovery codes left")` |
| `N(text)` | A text kept in a list or table and translated where it is shown (with `T(label)`). | `(RuleAction.Block, N("Block the request (403)"))` |
| `F(text, values…)` | An English message passed on to a page (an error, a "saved" notice). The page shows it with `Message(…)`, which finds the template again and translates it. | `F("Route '{0}' no longer exists.", name)` |
| `Message(text)` | Showing a message that was made elsewhere: configuration check errors from `Waf.Core`, validation messages, stored notices. Prefixes such as `Route 'api', destination #2:` are translated separately. | `<li>@Message(error)</li>` |

Rules:

- Values go in placeholders (`{0}`), never in pieces glued together, so each language can order its words.
- A sentence with a link or bold text is one key with the markup in it (`TM`), not several pieces.
- Validation attribute texts (`[Required(ErrorMessage = "…")]`) are constants; they are translated where they are
  shown, and a test checks that each has a translation.

## Adding or changing a text

1. Write the English text in the code with one of the helpers.
2. Add the key with its four texts to the four `.resx` files (keep them sorted by key).
3. Run the unit tests: `TranslationTests` fails for a key that is missing in a language, an empty translation,
   placeholders that differ from the English text, and an interpolated string (`T($"…")`) used as a key.
   The integration test `TranslatedPagesTests` renders every page for a German browser and fails on English text.

## What stays English

- Data the user entered: names, descriptions, host names, comments.
- Texts stored before they are shown, such as audit log summaries and configuration version comments, keep the
  language they were written in. Known system texts among them (for example "Imported from appsettings at startup.")
  are translated when they are shown.
- The service log, `wafctl`, the installers and the documentation.
- Names: HTTPS, HSTS, SNI, Let's Encrypt, Anthropic, Claude, `wafctl`, JSON, PFX, PEM, DHCP, MAC, SOAP, IIS, and
  setting names such as `Gateway:EventLog:Enabled` or `Settings.Acme.Email`.
- Technical details inside some error messages (for example the text of an exception, or an ACME server's reply).

## Glossary

| English | Nederlands | Français | Deutsch |
|---|---|---|---|
| admin UI | beheeromgeving | interface d'administration | Verwaltungsoberfläche |
| dashboard | dashboard | tableau de bord | Übersicht |
| route | route | route (f.) | Route |
| rule | regel | règle (f.) | Regel |
| rate limit | snelheidslimiet | limite de débit (f.) | Ratenlimit |
| target | doel | cible (f.) | Ziel |
| backend | backend | backend | Backend |
| failover (backend) | failover(-backend) | (backend de) secours | Ausweichziel, Ausweich-Backend |
| health check | statuscontrole | contrôle de santé | Statusprüfung |
| detection only | alleen detectie | détection seule | nur erkennen |
| attack detection | aanvalsdetectie | détection des attaques | Angriffserkennung |
| detection exclusion | detectie-uitzondering | exclusion de détection | Erkennungsausnahme |
| false positive | vals positief | faux positif | Fehlalarm |
| block / allow / log only | blokkeren / toestaan / alleen loggen | bloquer / autoriser / journaliser seulement | blockieren / erlauben / nur protokollieren |
| request log | verzoekenlogboek | journal des requêtes | Anfrageprotokoll |
| audit log | auditlogboek | journal d'audit | Audit-Protokoll |
| service log | servicelogboek | journal du service | Dienstprotokoll |
| configuration version | configuratieversie | version de configuration | Konfigurationsversion |
| restore / roll back | terugzetten / terugdraaien | restaurer / annuler | wiederherstellen / zurücksetzen |
| backup | back-up | sauvegarde | Sicherung |
| certificate | certificaat | certificat | Zertifikat |
| host name | hostnaam | nom d'hôte | Hostname |
| client IP | client-IP | IP du client | Client-IP |
| sign in / sign out | aanmelden / afmelden | se connecter / se déconnecter | anmelden / abmelden |
| two-factor sign-in | aanmelden in twee stappen | connexion à deux facteurs | Zwei-Faktor-Anmeldung |
| recovery code | herstelcode | code de récupération | Wiederherstellungscode |
| remote access | toegang op afstand | accès à distance | Fernzugriff |
| template / preset | sjabloon / voorinstelling | modèle / préréglage | Vorlage / Voreinstellung |
| AI assistant | AI-assistent | assistant IA | KI-Assistent |
| proposal | voorstel | proposition | Vorschlag |

Forms of address: *u* (Dutch), *vous* (French), *Sie* (German). French typography: a space before `:`, `;`, `?`
and `!`, and « » around names; German uses „ “.
