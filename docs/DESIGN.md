# DomainScope — UI audit and redesign spec

Status: proposal, 2026-10-09, revised the same day after a design review ([Review notes](#review-notes)).
Scope: the web app (`index.html`, `assets/`). The CLI, the runner and the
data files are out of scope. This spec supersedes the navigation and density parts of
[ROADMAP.md › UI upgrade spec](ROADMAP.md#ui-upgrade-spec); the rest of that section still stands.

**In one paragraph.** Each tool is strong on its own, but the UI was built one wave at a time and it
shows. The 20 tools sit in six groups that mix verbs and nouns. The start page is a scanning tool,
not the user's workspace. Every view brings its own page header, input card, run-button position,
result header, action row, stat tiles and empty state: 17 result headers, 11 stat-tile variants,
8 empty-state variants, 30 font sizes and no spacing tokens. On a 900 px screen results start between
y≈380 and y≈620, because the full form stays above them. On a 375 px phone the chrome is 98 px,
purpose lines run to 7 lines, and in five tools the run button is off the first screen.

The redesign keeps the stack, the routes, the privacy model and the colours. It adds:

- one page template with named regions;
- a result header with a status summary and four standard actions in a fixed order;
- a compact query bar once a result is on screen;
- a token set: 7 type sizes, a 4 px spacing grid, radii, elevation, focus and density;
- six nav groups by job, and a single bar on phones;
- a Home dashboard built from data the browser already holds, plus three small additive fields
  that make its counts true (§4.2).

There are six phases, each shippable alone; phase 1 ships in three steps (tokens, shell, Home).
Phase 1 also takes roughly 75–85 KB gzip off the start route.

Contents

1. [Audit](#1-audit)
2. [Principles](#2-principles)
3. [Information architecture](#3-information-architecture)
4. [Home dashboard](#4-home-dashboard)
5. [Page template](#5-page-template)
6. [Design tokens](#6-design-tokens)
7. [Component inventory](#7-component-inventory)
8. [Phased rollout](#8-phased-rollout)
9. [What not to change](#9-what-not-to-change)
- [Appendix A — new strings (EN / TR)](#appendix-a--new-strings-en--tr)
- [Appendix B — screenshots](#appendix-b--screenshots)
- [Appendix C — decisions for the owner](#appendix-c--decisions-for-the-owner)
- [Review notes](#review-notes)

---

## 1. Audit

### 1.0 Method

- **Screenshots: 269 viewport shots plus 178 full-page shots** at 1440×900 and 375×812, light and
  dark, mostly EN with TR samples. They cover:
  - every view's empty state;
  - a result state for 19 views, driven with the offline fakes of `tests/e2e` (no live network);
  - the shell's dialogs and menus.
- **Measurements:**
  - field and run-button positions, read with the CDP helper;
  - CSS statistics, from `grep` over `assets/css`;
  - start-route bytes, computed the same way as `tests/js/start-route.test.js`.

Screenshot names are `<view>-<device>-<theme>-<lang>-<state>[-at].png`. `-at` means scrolled to the
result header. They are cited below as `before/…`, and [Appendix B](#appendix-b--screenshots) says
where they are and how to make them again.

### 1.1 Information architecture and navigation

| # | Problem | Evidence |
|---|---|---|
| IA1 | **The groups mix two axes**: verbs ("Discover") and object types ("DNS tools", "IP addresses", "Mail & domain"). As a result, related tools end up apart: Domain Health is under *Mail & domain* while Domain overview is under *Discover*. Monitoring, a watch tool, sits in *Setup & info* next to Servers and About, while Domain portfolio, also a watch tool, is under *Mail & domain*. | `before/subdomains-desktop-light-en-empty.png` |
| IA2 | **There is no home.** `#/` opens Subdomains, so a returning MSP lands in a scan form, not in their customer's workspace. The workspace holds recent domains, the CT baseline, registration snapshots, accepted risks, the rollout board and DMARC history. That data shows only inside the tools and in the Workspaces dialog. | `before/shell-workspaces-desktop-light-en.png` |
| IA3 | **Twenty links, all the same weight.** At heights ≤ 1000 px the group labels shrink to 13 px lines with 1–2 px gaps, and the groups blur into one list. At ≤ 760 px the labels disappear. | `before/domain-desktop-light-en-empty.png`, `before/shell-laptop-1366x768-light-en.png` |
| IA4 | **720–900 px:** the sidebar turns into a sideways strip that shows about 6 of the 20 tools and no groups. | `before/shell-tablet-860-light-en.png` |
| IA5 | **Phone:** two bars stack (header and Tools bar, 98 px measured) before any content. The Tools sheet lists 20 tiles with no search, and the palette button is hidden on phones. | `before/shell-phone-toolsmenu-light-en.png`, `before/subdomains-phone-light-en-empty.png` |
| IA6 | The palette (Ctrl/⌘+K) is the fastest way in, but its header entry is a bare magnifier with no hint of the shortcut. The GitHub link uses header space that search could use. | `before/lookup-desktop-light-en-empty.png` |
| IA7 | **Two tools share one page:** Retire an IP also hosts "Compare the old and the new server" under its empty state. Servers puts its three sub-pages as tabs *above* its own privacy notice. | `before/retire-desktop-light-en-empty.png`, `before/inventory-desktop-light-en-empty.png` |
| IA8 | **Cross-tool links have no fixed wording or place:** "More about this domain:" under the Health hero; "More about this name:" under the Global DNS stats; buttons inside the Lookup summary; "Open in Domain Health →" on overview cards. | `before/health-desktop-light-en-result.png`, `before/global-desktop-light-en-result-at.png`, `before/lookup-desktop-light-en-result.png`, `before/domain-desktop-light-en-result.png` |

### 1.2 Start page and first run

| # | Problem | Evidence |
|---|---|---|
| F1 | **First visit:** the Subdomains page, with a "New here?" strip above its header. There are three levels of heading before the field (strip title, H1 *Subdomains*, hero *Which domain should we scan?*). The field starts at y=558 on desktop and y=590 at 375×812. | `before/subdomains-desktop-light-en-empty.png`, `before/subdomains-phone-light-en-empty.png` |
| F2 | After a dismissal or the first run, the job picker leaves the start page for good; only About › Where to start keeps it. Its five jobs cover nothing for IPs or for watching many domains. | `before/about-desktop-light-en-empty.png` |
| F3 | **Nothing introduces workspaces, the MSP's unit of work.** The header says "Default" and never suggests one workspace per customer. | `before/subdomains-desktop-light-en-empty.png` |
| F4 | The first screen explains a lot (Subdomains: three source tiles and two notes) but shows nothing of the user's own state: servers saved, last checks, expiries. | `before/full/subdomains-desktop-light-en-empty.png` |
| F5 | **Empty states repeat the page description.** Domain overview says its purpose in the header, then again in a 260 px empty card. | `before/domain-desktop-light-en-empty.png` |

### 1.3 Consistency between views

| # | Problem | Evidence |
|---|---|---|
| C1 | **Page header.** The structure is sound (42 px icon, 23 px H1, description), but descriptions take 1–3 lines on desktop and 2–7 on a phone. Certificate estate and Monitoring both reach 7 lines at 375 px. | `before/estate-phone-light-en-empty.png`, `before/monitor-phone-light-en-empty.png` |
| C2 | **Privacy notices come in four treatments:** (1) a green *success* alert above the input — Zone File, Certificate estate, DMARC & TLS reports, Monitoring, Servers (`Alert({ variant: 'ok', icon: 'lock' })` in zone.js:1298, estate.js:514, reports.js:1351, monitor.js:641); (2) a lock line under the input — Certificate, Renewal readiness, Reverse DNS, Retire an IP, DNS change request; (3) plain muted text — IP Intel, Domain overview, Domain portfolio; (4) nothing at all — Domain Health, DNS Lookup, Global DNS, Bulk Resolve. | `before/zone-desktop-light-en-empty.png` vs `before/health-desktop-light-en-empty.png` |
| C3 | **Input areas come in five styles:** a hero card with its own 19 px heading and a 48 px field (Subdomains); a labelled field in a plain card (Domain overview, Health, Global DNS, Lookup); a card with an icon header (Zone File, Certificate, Bulk Resolve, Estate, Monitoring); a numbered wizard (SSL Targets); an editor with a preview (Servers). | `before/subdomains-desktop-light-en-empty.png`, `before/health-desktop-light-en-empty.png`, `before/bulk-desktop-light-en-empty.png`, `before/scan-desktop-light-en-empty.png` |
| C4 | **The run button has six placements:** (1) inline right of the field — Subdomains, Domain overview, Health, Global DNS, Lookup; (2) bottom-right after the form — Renewal readiness, Retire an IP, Reverse DNS, IP Intel, Portfolio, DNS change request; (3) full width at the foot of a side column — Bulk Resolve; (4) in the card footer — DMARC; (5) left, under the drop zone — Monitoring; (6) a sticky bar — SSL Targets only. The same "run" meaning carries five different icons (search, play, id-card, activity, check-circle). | `before/<tool>-desktop-light-en-empty.png` (all 20) |
| C5 | **Examples come in five forms:** pill chips (Subdomains); mono links (Health, Global DNS, Lookup); an "Example" ghost button (IP Intel); an "Example: AS3333" link (Reverse DNS); "Try a sample" buttons (Zone File, Certificate, SSL Targets). | `before/<tool>-desktop-light-en-empty.png` |
| C6 | **Result headers: 17 implementations, none shared** — `.sub-run-head`, `.dov-head`, `.zone-summary`, `.scan-results-head`, `.cert-overview`, `.rnw-hero`, `.estate-overview`, `.glb-summary`, `.lkp-sum`, `.chg-hero`, `.ipi-results-bar`, `.ptr-results`, `.retire-head`, `.hlt-hero`, `.rpt-results-head`, `.pf-head`, `.mon-summary`. IP Intel's result has no title at all. Bulk Resolve and Reverse DNS show a progress card where a title should be. The verdict appears in five ways: a traffic light with a grade (Health); a red alert inside a card (Renewal readiness, Retire an IP); a warn alert above the stats (Global DNS); a box mid-card (DMARC); or no verdict at all. | `before/ip-desktop-light-en-result.png`, `before/bulk-desktop-light-en-result-at.png`, `before/renew-desktop-light-en-result-at.png`, `before/global-desktop-light-en-result-at.png` |
| C7 | **Actions: two areas for one result.** The page header holds Copy link / Run again and the result header holds Copy summary / Plain text (Subdomains, Lookup, Health, Domain overview, IP Intel, Portfolio). Copy link exists in 10 tools and Report in 3. Copy summary exists in 16 tools, but not in Reverse DNS or Bulk Resolve. Alignment is right in most tools, left in Estate, and floating with no header in DNS change request. Rows of 7–8 equal-weight buttons: Lookup (Copy all, Copy summary, Plain text, Explain, DNSSEC chain, Global DNS, Domain Health); Certificate (Find servers, Renewal readiness, Download PEM, Download full chain, Copy PEM, Copy summary, Plain text, Remove); SSL Targets (five downloads, Copy summary, Plain text, then CSV/JSON again in the table toolbar). | `before/cert-desktop-light-en-result.png`, `before/scan-desktop-light-en-result-at.png`, `before/estate-desktop-light-en-result.png`, `before/change-desktop-light-en-result-at.png` |
| C8 | **A progress card stays after the run** ("Done 8/8 · 100%") in Bulk Resolve, Reverse DNS and SSL Targets, taking 100–160 px. | `before/bulk-desktop-light-en-result-at.png`, `before/ptr-desktop-light-en-result-at.png`, `before/scan-desktop-light-en-result-at.png` |
| C9 | **Stat tiles: 11 per-view variants** (`.bulk-stats`, `.estate-stats`, `.glb-stats`, `.inv-stats`, `.ipi-stats`, `.mon-stats`, `.ptr-stats`, `.retire-stats`, `.rpt-stats`, `.scan-stats`, `.sub-stats`) of one 90–110 px tile with a 3 px coloured stripe. The stripes mix statuses with classification kinds (Cloudflare orange, CDN purple, Direct teal, error red), so a row of seven reads as a rainbow. The pressed state (2 px accent border) looks like keyboard focus. Zero tiles take full space ("Critical status 0"); only IP Intel folds zeros into a sentence. | `before/scan-desktop-light-en-result-at.png`, `before/portfolio-desktop-light-en-result-at.png` |
| C10 | **Alerts used as layout.** SSL Targets stacks six full-width alerts after its stats (1 warn, 5 info). Blue info alerts also carry hints that are not alerts (IP Intel's "Find domains asks HackerTarget…"). | `before/scan-desktop-light-en-result-at.png`, `before/ip-desktop-light-en-result.png` |
| C11 | **Tabs** have icons in six views (Certificate, SSL Targets, Estate, Reports, Bulk, Servers) and none in the rest (Subdomains, Zone, Portfolio, DNS change request). Servers puts them above the privacy notice. On phones, 7–8 tabs overflow and the last label is clipped with no hint ("Exposure audi", "Certi", "Pr"). | `before/inventory-phone-light-en-empty.png`, `before/portfolio-phone-light-en-result-at.png` |
| C12 | **Tables.** DataTable is shared and solid, but the same kind of table has three ways to filter: click a stat tile, a segmented control (Subdomains) or a "Show" select (SSL Targets, Bulk, Reverse DNS, Estate, Portfolio). SSL Targets adds four checkboxes. Footers read "7 rows" in one view and "Showing 5 of 5 matching (9 total)" in another. On phones, Subdomains, Estate and Monitoring rows become cards, while Bulk Resolve, IP Intel and Lookup's record tables scroll sideways inside their card with the last column clipped. | `before/bulk-phone-light-en-result-at.png`, `before/lookup-phone-light-en-result-at.png` |
| C13 | **Badges.** One pill shape serves facts, statuses, filters and clickable "Try" chips, while some static tags elsewhere are 4 px rectangles (`.sub-origin`). Rows in Portfolio, Estate and Monitoring carry 3–6 coloured badges each. | `before/estate-desktop-light-en-result-at.png`, `before/monitor-desktop-light-en-result-at.png` |
| C14 | **Empty states come in three forms:** a 230–260 px card (11 tools), bare centred text (Certificate, Estate, Reports, Monitoring) or a dashed box (Servers). There are 8 per-view `-empty` classes. | `before/cert-desktop-light-en-empty.png`, `before/inventory-desktop-light-en-empty.png`, `before/domain-desktop-light-en-empty.png` |
| C15 | **Expiry colours disagree.** Registration days are red under 30 and amber under 60 (lib/portfolio.js). Certificate days are red under 7 and amber under 21 in Monitoring (`MONITOR_WARN_DAYS`). Certificate estate uses buckets of <7 / <30 / <90 days, and the CT radar is configurable (30/14/7). So "12 days left" is red in Portfolio while "15 days left" is amber in Monitoring. | `before/portfolio-desktop-light-en-result-at.png`, `before/monitor-desktop-light-en-result-at.png`, `before/estate-desktop-light-en-result-at.png` |

### 1.4 Hierarchy, density, type, spacing, colour, dark mode, mobile

| # | Problem | Evidence |
|---|---|---|
| H1 | **Results start low** because the form keeps its full size after a run. Top of the result header at 1440×900: Domain overview ≈380, Health ≈390, Subdomains ≈520, Lookup ≈540, Portfolio (TR) ≈620. Zone File and Certificate already fold their input into one line ("Import another file…", "Load another file"), but only file tools do. | `before/portfolio-desktop-light-tr-result.png`, `before/lookup-desktop-light-en-result.png`, `before/zone-desktop-light-en-result.png` |
| H2 | **Spacing: no tokens.** There are 20 distinct `gap` values and 33 distinct padding values. The gap from form to result is 24 px in most tools and 48 px in Health, Reverse DNS and Retire an IP. | `before/health-desktop-light-en-result.png`, `before/ptr-desktop-light-en-empty.png` |
| H3 | **Type:** 30 distinct font sizes (10–40 px, plus rem/em values), and weights 550/650 that Linux system fonts round to normal or bold. On the start page two titles compete: the 23 px H1 and the 19 px hero title. | `before/subdomains-desktop-light-en-empty.png` |
| H4 | **Structure is heavy.** Every block is a 12 px-radius card with a shadow, cards nest in cards (Zone's Next steps, Lookup's record tables) and the page padding is 28/32 px. The result is calm but costs density. | `before/zone-desktop-light-en-result.png` |
| H5 | **77 % of the CSS is per view** (289 KB of 378 KB raw), mostly re-implementing the same header, stats and action patterns. | — |
| K1 | **Green means "OK", except when it doesn't:** it also means "private" (the privacy alerts), "found over DNS" (`.sub-origin[data-tech="dns"]`) and "more than 90 days". | `before/subdomains-desktop-light-en-result-at.png` |
| K2 | **The accent blue does too many jobs:** primary button, links, the selected nav item and tab, a pressed tile, info alerts, "Input" / "Direct" badges. Selection, information and interaction share one hue. | `before/scan-desktop-light-en-result-at.png` |
| K3 | **Text contrast is fine overall:** every text token is ≥ 4.5:1 on surfaces in both themes. The one edge: `--text-3` (#687080) is 4.29:1 on `--surface-3` and 4.56:1 on `--bg`. | — |
| K4 | **Controls are below 3:1** (WCAG 1.4.11): field borders (`--border-strong`, 1.52:1 on white); the switch's off state (white thumb on a `--surface-3` track, 1.17:1); and, in dark mode, the primary button's hover (white on the literal `#3b78ea`, 4.15:1 for its label). | style.css `.input`, `.switch-track`, `.btn-primary:hover` |
| D1 | **Dark mode is close to parity:** same layout and tokenised colours (13 literal colours outside the token blocks, 9 of them in Global DNS, mostly its eight answer-group colours). Two rough edges: green privacy alerts become a bright band on near-black, and rows of stripes and badges get louder. | `before/zone-desktop-dark-en-empty.png`, `before/portfolio-desktop-dark-en-result-at.png` |
| M1 | **Phone chrome is 98 px** and purpose lines run up to 7 lines. Top of the primary field at 375×812: Zone File 661, DMARC 616, Monitoring 573, Servers 571, Estate 535. The run button is below the first screen in Bulk Resolve (1106), DNS change request (1051), Servers (1037), DMARC (938) and Renewal readiness. Only SSL Targets has a sticky run bar. | `before/bulk-phone-light-en-empty.png`, `before/renew-phone-light-en-empty.png` |
| M2 | **On phones, the result's actions wrap into 2–4 rows before any data** (Lookup: 4 rows; SSL Targets: 3). Stat tiles stack two per row at ~100 px each, so seven of them fill the first screen. | `before/lookup-phone-light-en-result-at.png`, `before/scan-phone-light-en-result-at.png` |
| M3 | **At 320 px the header is tight:** the target chip truncates to "exam…" next to TR\|EN, theme and settings. | `before/shell-phone320-health-light-en.png` |

---

## 2. Principles

1. **Answer first.** A result opens with one line of verdict and a count by severity, before any
   table. Once a run starts, the input folds to one row whose main field stays editable, so nothing
   jumps when the result lands and a new subject is one edit away. At 1440×900 every query tool's
   result header starts above y=300.
2. **One template, learned once.** Every tool has the same regions in the same order: purpose, input,
   run, result header, tabs, body. The same actions sit in the same place, under the same names.
   Differences are allowed only inside the body.
3. **Dense, calm, exact.** 32 px buttons, 36 px rows, seven type sizes, a 4 px spacing grid and
   flat neutral surfaces. Data is in mono with tabular figures. No decorative gradients. No cards
   inside cards unless the inner one is a table.
4. **Colour is status.** Red, amber, green and blue mean error, warning, OK and info, always
   with an icon and a word. Classification kinds keep their own palette, in kind tags only. Privacy
   notes, hints and "found by" labels are neutral.
5. **The workspace is home.** The app opens on the active customer's workspace, built from what the
   browser already holds. It sends nothing until a tool runs, and it says so.
6. **Say what is sent, quietly.** Each tool states in one neutral line next to its Run button what it
   sends and to whom. Details are one click away. The substance of today's privacy texts stays; only
   their weight changes.
7. **Fresh or flagged.** Every count on Home and in a result header says when it was measured. A
   fact read long ago (a registration snapshot from last month, a CT check from two weeks ago) is
   shown *as of* that date with a "Check again" link, never as a current fact. Relative times carry
   the absolute time.

---

## 3. Information architecture

### 3.1 Six jobs

Route ids do not change. Only `group` in `VIEWS` (app.js), `NAV_GROUPS` (lib/shellnav.js) and
the order of `VIEWS` change.

| Group id | EN label | TR label | Tools, in nav order | Why together |
|---|---|---|---|---|
| — | **Home** | **Ana sayfa** | Home (new, `#/home`, the default route) | the workspace at a glance |
| `investigate` | Investigate a domain | Alan adını incele | Domain overview · Domain Health · Subdomains · DNS Lookup | "a customer asks about example.com" |
| `certs` | Deploy & renew certificates | Sertifika kur ve yenile | SSL Targets · Certificate · Renewal readiness · Certificate estate | the certificate lifecycle, from file to every server |
| `change` | Change & migrate DNS | DNS’i değiştir ve taşı | DNS change request · Global DNS · Zone File · Retire an IP | plan a change, check it propagated, move zones, retire addresses |
| `network` | Map IPs to servers | IP’leri sunuculara eşle | IP Intel · Bulk Resolve · Reverse DNS | names → addresses → your machines |
| `watch` | Watch & report | İzle ve raporla | Domain portfolio · Monitoring · DMARC & TLS reports | many domains over time; customer-facing reports |
| `setup` | Setup & help | Kurulum ve yardım | Servers · About | the server list every tool uses; how the app works |

Notes:

- **Home has its own entry in `NAV_GROUPS`**, first and with no label (`{ id: 'home', labelKey: null }`).
  Home's `VIEWS` entry has `group: 'home'`. Without that entry, `groupViews` would put a view with
  no known group into *More tools* at the end of the list.
- **The last group is *Setup & help*, not *Workspace*.** A group that holds About is not the
  workspace. The workspace already has its own two places: the header switcher and Home.

- **Global DNS moves to *Change & migrate DNS*.** Its main job is "Is my change live everywhere?",
  which is already a start task. DNS Lookup links to it from the result header (§5.3, *Related*).
- **Bulk Resolve moves to *Map IPs to servers*:** its output is IP → server matches.
- **About stays in the nav** but is the last item. It is not a tool, so the palette ranks it below
  the tools.
- **Settings (DoH resolvers, parallelism, delete local data) and Workspaces** stay dialogs. They
  are reached from the header and listed in the palette. Theme and language are header controls,
  not settings.

### 3.2 Desktop (≥ 1100 px)

**Header (52 px)**: `brand · workspace switcher · current target | search … | TR|EN · theme · settings`

- The brand (logo + name) links to `#/home`. The `.brand-sub` subtitle stays in the DOM and shows from
  1280 px up.
- **Workspace switcher:** shows the workspace name, and the server count from 1280 px up
  ("Acme · 12 servers").
- **Current target chip:** unchanged ("Target example.com ✕", `session.target.label`), next to the switcher.
- **Search:** a 320 px button styled as a field, reading "Search tools, domains, IPs… Ctrl K". It
  replaces the bare magnifier and keeps `data-control="palette"`. It is a `<button>`, not an input,
  with `aria-keyshortcuts="Control+K Meta+K"`. The hint reads "⌘K" on Apple platforms.
- **TR|EN and theme:** stay as they are (`data-control="lang"` / `"theme"`).
- **Settings:** stays as an icon button (`data-control="settings"`).
- **GitHub:** leaves the header. The footer and About keep it.

**Sidebar (232 px)**:

- Home on top, then the six groups. Group labels are sentence case: 12 px, weight 600, `--text-3`.
- Each group has a 12 px gap above it and a 1 px `--border` rule between groups.
- Links: 13 px weight 500, 28 px tall, with an 18 px icon. The active link has a neutral
  `--surface-selected` background, `--text` text and a 2 px `--accent` inset bar on its left.
  Blue marks what you can act on, not what is selected (K2).
- **Busy dots and job rings:** unchanged (`.nav-job`).
- **The height tiers stay** (≤ 1000 px: compact, 24 px links; ≤ 760 px: labels sr-only, rules
  only). The e2e check "24 tools in view at 1366×657" still has to pass, with Home counted.
- **Footer of the sidebar: one block of two lines** — "12 servers · DoH: Cloudflare → …" and
  "Runs in your browser". It is hidden in the ≤ 760 px tier.

```
BEFORE (1440×900)                                   AFTER (1440×900)
┌───────────────────────────────────────────────┐   ┌───────────────────────────────────────────────────────┐
│◉ DomainScope [▣ Default▾]   TR EN ◐☀☾ ⌕ ⚙ GitHub│   │◉ DomainScope [▣ Acme · 12 servers▾] [◎ Target ex.com ✕] │
│                                               │   │        [⌕ Search tools, domains, IPs…  Ctrl K]  TR EN ◐ ⚙│
├────────────┬──────────────────────────────────┤   ├──────────────┬────────────────────────────────────────┤
│DISCOVER    │ New here? Pick a job      [×]    │   │ ⌂ Home       │ (Home dashboard, §4)                    │
│ Subdomains │ [job][job][job][job][job]        │   │              │                                         │
│ Domain ov… │ ◫ Subdomains (H1 23px)           │   │ Investigate  │                                         │
│ Zone File  │   2-line description             │   │ a domain     │                                         │
│CERTIFICATES│ ┌ Which domain should we scan? ─┐│   │  Domain ov…  │                                         │
│ SSL Targets│ │ 3-line explainer               ││   │  Domain Hea… │                                         │
│ …20 links, │ │ [⌕ example.com………] [ Scan ]   ││   │  Subdomains  │                                         │
│ 6 groups   │ └────────────────────────────────┘│   │  DNS Lookup  │                                         │
│────────────│ Where do the subdomains come from│   │ ──────────── │                                         │
│No servers… │ [DNS][CT][Passive] + 2 notes     │   │ Deploy & re… │                                         │
│DoH: … (2l) │                                  │   │  SSL Targets │                                         │
│Runs in…    │                                  │   │  …           │                                         │
└────────────┴──────────────────────────────────┘   │ ──────────── │                                         │
                                                    │ Setup & help │                                         │
                                                    │  Servers     │                                         │
                                                    │  About       │                                         │
                                                    │ 12 servers · │                                         │
                                                    │ DoH: CF → …  │                                         │
                                                    └──────────────┴────────────────────────────────────────┘
```

### 3.3 Tablet (720–1099 px)

The sideways strip goes away. The header gets a **Tools** button (`data-control="nav-menu"`, as on
phones) that opens the sidebar as a **drawer**: a `<dialog>` 280 px wide on the left, with the same
groups, focus trapped, closed with Esc or a backdrop click. The content then uses the full width,
which wide tables need. The 900 px breakpoints inside the view stylesheets do not change.

The header keeps one row at 720 px by collapsing in this order: the search button becomes an icon
button (⌕), the theme control becomes today's single cycle button (`data-control="theme-cycle"`),
the target chip truncates its value at 160 px, and the workspace switcher drops its server count.

### 3.4 Phone (< 720 px)

**One bar, 52 px:** `logo (home) · [☰ <current tool> ▾] · TR|EN · ⚙`

- **Tools button:** flexible width. Its label is the current tool's name, which truncates with an
  ellipsis; the icon and the chevron always show. A visually hidden "Tools:" prefix makes the
  accessible name "Tools: DNS Lookup", which keeps the visible text inside it. It has
  `aria-haspopup="dialog"` and `aria-expanded`. `.nav-menu-current` merges into `.nav-menu-btn`,
  and `data-control="nav-menu"` is kept.
- **TR|EN and Settings stay in the bar:** two 36 px segments and a 40 px icon button. About 48 e2e
  steps in 26 suites switch the language at phone widths through
  `[data-control="lang"] [data-value=…]` (`setLangUi` and its seven copies). Five suites'
  `deleteAllLocalData` helpers click `[data-control="settings"]`. Both selectors must keep working,
  with no change to the tests.
- **Theme and the current target** move into the Tools sheet footer, next to "Workspace: Acme ·
  Switch or manage" (already there).
- **There is no separate ⌕ button.** On phones the Tools sheet *is* the palette (below).
- **Width check at 320 px, with touch targets:** side padding 2 × 12 + logo 28 + TR|EN 72 +
  Settings 40 + three 6 px gaps = 182 px. That leaves ≈ 138 px for the Tools button: short names
  fit, and "Domain portfolio" truncates. The first draft's bar (Tools 150, TR|EN, theme and ⌕)
  needed ≈ 390 px once measured: today's TR|EN is 80 px, and touch buttons are 40 px. It did not fit
  at 320 px, nor at 375 px.

**Tools sheet = the palette on phones** (`Modal` size `sheet`, full height):

- **On top, the palette's box** (ui/palette.js, lib/palette.js `parseSubject`). It finds tools,
  and a domain, host, IP, network or AS gets its actions, exactly as Ctrl K does on a desktop: one
  search, not two. The box is not focused when the sheet opens, so the keyboard does not cover the
  tiles.
- **While the box is empty:** Home and the six groups as today's two-column tiles. The sheet stays
  a `dialog.navmenu-modal` and the tiles stay `.navmenu-link[data-view]`, which carry.e2e clicks.
- **The footer:** Workspace (switch or manage), Current target (✕), Theme (Auto / Light / Dark).
- **Loading:** the tiles render at once from app.js. The box attaches when ui/palette.js has
  loaded, on the first open only.
- **The header's `[data-control="palette"]` button** stays hidden on phones, as shell.e2e asserts
  today.

**Sticky run bar:** every query tool gets the `.run-bar` behaviour that SSL Targets has today
(§5.1, region 3). The bar appears when the inline Run button scrolls out of view while the input
has a value. It keeps a focused field clear of itself with `scroll-padding-bottom`, as scan.css
does with `--scan-runbar-h`, so the bar never hides the focused element (WCAG 2.4.11).

```
BEFORE (375)                              AFTER (375)
┌───────────────────────────────────┐     ┌───────────────────────────────────┐
│◉ DomainScope        [TR|EN] ◐  ⚙  │52   │◉ [☰ DNS Lookup          ▾] TR|EN ⚙│52
├───────────────────────────────────┤     ├───────────────────────────────────┤
│[☰ Tools ▾]  ⌕ DNS Lookup          │46   │DNS Lookup                       ⓘ │
├───────────────────────────────────┤     │Query any record type, with DNSSEC │
│◫ DNS Lookup                       │     │status and the raw answer.         │
│  Query any record type with       │     │┌─────────────────────────────────┐│
│  DNSSEC status, parsed fields…    │     ││[example.com…………………] [▶ Look up]││
│ ┌───────────────────────────────┐ │     │└─────────────────────────────────┘│
```

### 3.5 Search, palette and cross-links

- **The palette is the universal entry** (lib/palette.js `parseSubject`, `PALETTE_ACTIONS`).
  Home's quick-start field (§4) uses the same parser, so typing on Home and pressing Ctrl K behave
  the same way.
- **Cross-tool links** move to a single *Related* row in the result header (§5.3). Wording: EN
  "Also check:", TR "Ayrıca bakın:", with up to four tools, each with its icon.
  - Links that only *fill* another tool use `fillRoute` (`run=0`), as now.
  - Actions that hand data over ("Add names to a scan", "Find servers for this certificate") are
    *next steps* in the body, not in the action row.

### 3.6 Routes

- **No route is renamed.** `DEFAULT_VIEW` becomes `'home'`, and `#/` and unknown routes open Home.
  Old links (`#/subdomains?domain=…`) keep working.
- `index.html`'s brand link changes from `#/subdomains` to `#/home`. The manifest `start_url` stays
  `./`, which now lands on Home; Home is `offline: true`.

---

## 4. Home dashboard

### 4.1 Purpose and rules

**`#/home` (views/home.js, css/views/home.css)** answers three questions for the active workspace:
*What needs attention? What was I doing? Where do I start?*

Rules:

- **No network.** Home reads `state` (workspace parts, inventory, settings) and the page session
  only. It is `offline: true` and never calls `ctx.getDns()`, `fetch` or the Globalping client.
  The privacy line says so: EN "Home reads only what this browser keeps; it sends nothing." / TR
  "Ana sayfa yalnızca bu tarayıcının sakladıklarını okur; hiçbir şey göndermez."
- **Counts, not reports.** Every card is one line with a count and a link to the tool that has the
  details. Home never re-implements a tool's table.
- **Cheap on the start route, and no second copy of any rule.**
  - **First paint:** Home paints its title, quick start, *Recent domains*, *Start a job* and *This
    workspace* from `state` at once.
  - **The counts of *Needs attention*** come from a new DOM-free `lib/homedigest.js`. home.js loads
    it with a dynamic `import()` right after that first paint, so neither it nor what it imports is
    on the start route; the start-route test asserts this. While it loads, the card shows one muted
    line, "Reading this workspace…". It costs ≈ 30 KB gzip on the first visit, ≈ 45 KB when the
    workspace has a DMARC history (lib/dmarchistory.js is a second dynamic import). After that it
    comes from the service worker's cache.
  - **It never re-implements an owner's rule.** It imports the owners' small DOM-free readers:
    lib/regwatch.js `readRdapSeen`, lib/waivers.js `readWaivers` / `waiverState`, lib/rollout.js
    `parseRollout`, lib/dmarchistory.js `rollup` and lib/expiry.js (§6.2). It also imports a new
    lib/regstatus.js: `statusRisk`, `lockLevel` and `CRITICAL_STATUSES` move there from
    lib/portfolio.js, which re-exports them (the precedent is lib/ip.js, split out of
    lib/netinfo.js). The first draft's 4 KB parser would have been a second copy of these formats
    and rules, and it already disagreed with them (rows below).
  - **What it never imports:** lib/ctwatch.js (it pulls x509.js), lib/policy.js, lib/portfolio.js.
  - **Tests:** `tests/js/homedigest.test.js` feeds it output from the real writers.
- **Fresh or flagged** (principle 7). Every row says when its data was read ("CT checked 3 d
  ago"). Each kind has a staleness limit: a registration snapshot 7 days, a CT check 14 days, a
  Monitoring import 2 days. Past the limit, a row keeps its count and its severity but reads "as of
  <date> · Check again". The link fills the tool and sends nothing. Without this rule, a domain
  renewed after the last check would show as expiring.
- **One row per kind and severity**, naming up to three domains and then "+n more". So 40 expiring
  domains make one row, not 40. Each row is one link (the whole row; ▸ is decoration), so a screen
  reader's link list reads the row's text, not "Open" six times.
- **Cards with nothing to show are left out**, never shown empty. *Results in this tab* is empty on
  a fresh tab, since the page session lives in memory only.
- **Title.** H1 is the workspace label: the name, or "Default workspace" / "Varsayılan çalışma
  alanı". The purpose line gives the facts, e.g. "12 servers · 7 recent domains · last activity
  2 h ago". `document.title` reads "Acme · DomainScope".
- **A workspace switch re-renders Home** (the shell already re-mounts the current view).

### 4.2 What it shows, and from where

| Card | Source (in the browser; **new** marks the three additive fields) | Computation (lib/homedigest.js) | Severity | Link |
|---|---|---|---|---|
| **Quick start** field | — | lib/palette.js `parseSubject`; the actions offered for the subject's kind | — | the action's tool via `actionRoute` (fills, sends nothing) |
| Needs attention: certificate expiry | `state.workspaceData('ctSeen')`, per domain: `at`, and a **new additive `due`** list. `due` holds the expiry days of that check's *current* certificates (lib/ctwatch.js `analyzeCt` rows with `current`). The CT tab writes it with the baseline, and `readSeen` keeps it. Home does **not** use the baseline's `ids`: they keep every certificate seen until it expires, so a certificate already replaced by its renewal would count | `due` days by the certificate bands (§6.2); `at` older than 14 days → "as of" | error / warn | Domain portfolio › Certificates (CT) with the domains filled in |
| Needs attention: registration expiry | `state.workspaceData('rdapSeen')` through `readRdapSeen` (`at`, `state`, `expires` YYYY-MM-DD) | days to `expires`, by the registration bands (§6.2); `not-found` → error; `at` older than 7 days → "as of" | error / warn | Domain portfolio with those domains |
| Needs attention: open registry risks | `state.workspaceData('rdapSeen')` (`statuses`, RDAP spelling, lower case) | lib/regstatus.js `statusRisk`, the Portfolio's own rule: `critical` (a hold, redemption period or pending delete) → error; `pending-transfer` → error; `hijack` (no transfer prohibition at all, whether client, server or plain) → warn. The first draft's rule ("`client transfer prohibited` missing → warn") would have flagged domains under a registry lock and missed pending transfers | error / warn | Domain portfolio with those domains |
| Needs attention: accepted risks | `state.workspaceData('waivers')` through `readWaivers` (`expires`, `kind`, `domain`) | `waiverState` = `expiring` (`WAIVER_SOON_DAYS`, 14 days) → warn; `expired` → info ("counts again") | warn / info | Workspaces › Accepted risks |
| Needs attention: rollout | `state.workspaceData('rollout')` through `parseRollout` | per board changed in the last 30 days: servers verified out of the total. A stored board keeps only the rows someone ticked, so the total needs a **new additive `total`** on the board. The Rollout tab writes it when it renders with a scan. Without it the row says "3 verified, 2 installed". A board is open while a row is not verified or, with `total`, while fewer than `total` are | info | SSL Targets › Rollout |
| Needs attention: nightly results | a **new workspace part `digests`**: JSON text ≤ 16 KB, `{ monitor: { at, imported, targets, bad, expiring, incomplete } }`, counts only. The Monitoring view writes it after an import. The first draft used the page session, which lives in memory only: a reload empties it, so the row would almost never be there when Home opens | as written; `at` older than 2 days → "as of" | error / warn | Monitoring |
| Needs attention: jobs running | ui/jobs.js: `runningWork()` gives names only, so jobs.js exports `jobList()` (`view`, `fraction`, `startedAt`), and `startJob` takes an optional `subject` | one row per job, with its ring | running | the job's tool |
| Needs attention: servers list | `state.inventory` parse warnings | warnings count > 0 | warn | Servers |
| Needs attention: DMARC | `state.workspaceData('reportHistory')` (up to 4 MB of JSON) | lib/dmarchistory.js `rollup()` over 30 days: verdict `enforced-losing` (p=reject refuses mail of known senders) → error; `fix-first` → warn. Computed last, in an idle callback, so a large history never delays the other rows | error / warn | DMARC & TLS reports › History |
| **Recent domains** | `state.workspaceData('recent')` (≤ 20, `{ value, at }`) | newest 8, relative time | — | name → set as current target; quick actions Health · Overview · Subdomains · Lookup (`fillRoute`) |
| **Results in this tab** | `pageSession.kept(id)` for every view (memory only: empty after a reload, and then the card is left out) | tool, subject, time and, when the view's `result()` returns the new optional `status: { error, warn }` (kept by lib/session.js `normalizeResult`), its open-risk counts; up to 6 | error / warn when counted | `navHref(id)` (brings the kept result back) |
| **Start a job** | `START_TASKS` (+ new `portfolio` task) | — | — | the task's tool |
| **This workspace** | `state.inventory.servers.length`, `expectedCas`, `notes`, `origins`, `waivers` | counts; the first line of the notes | — | Servers · Workspaces dialog |

Ordering inside *Needs attention*: error → warn → running → info, then soonest first. At most six
rows, then "Show all (n)". With data but nothing due, one OK row is shown: "Nothing needs attention ·
CT checked 2 days ago · registrations checked 2 days ago".

**The three additive fields** are the only data changes Home needs: ctSeen's `due`, the rollout
board's `total` and the `digests` part. Their owners write them (phase 1c). An older reader drops
an unknown field or part harmlessly, and a workspace hand-over file carries them like any other
part (lib/workspace.js loops over `WORKSPACE_PARTS`). Until an owner has run once after the
update, Home shows that row without its count ("CT: check once to see expiries here").

### 4.3 Layout

```
DESKTOP 1440 — populated
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ Acme                                                                     [Manage ▸]        │ h1 20px
│ 12 servers · 7 recent domains · last activity 2 h ago                                      │ purpose
│ ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ⌕  Domain, host name, IP address, network or AS number                    [Open ▸]     │ │ quick start
│ │    example.com → Domain overview · Domain Health · Subdomains · DNS Lookup · Global DNS │ │ (actions appear
│ └───────────────────────────────────────────────────────────────────────────────────────┘ │  as you type)
│ Needs attention                                                                            │
│ ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ✕ 2 certificates expire within 7 days        example.com, shop.example.org    Open ▸  │ │
│ │ ✕ Last night: 3 bad changes on 2 targets     Monitoring, imported 09:12        Open ▸  │ │
│ │ ⚠ Registration expires in 45 days            example.org · as of Oct 2         Open ▸  │ │
│ │ ⚠ 1 accepted risk ends this week             example.com · dmarc.policy-none   Open ▸  │ │
│ │ ◔ Subdomains scan running — 45 %             example.net                       Open ▸  │ │
│ └───────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌ Recent domains ─────────────────────────────────┐ ┌ Start a job ──────────────────────┐ │
│ │ example.com       2 h   Health Overview Subd. ⌕  │ │ ◫ Find every subdomain          ▸ │ │
│ │ example.org       1 d   Health Overview Subd. ⌕  │ │ ◎ Where must this cert go?      ▸ │ │
│ │ shop.example.net  3 d   Health Overview Subd. ⌕  │ │ ∿ Check a domain's health       ▸ │ │
│ └──────────────────────────────────────────────────┘ │ ⊕ Is my DNS change live?        ▸ │ │
│ ┌ Results in this tab ────────────────────────────┐ │ ▤ Import a zone file            ▸ │ │
│ │ ∿ Domain Health  example.com    10:51            │ │ ▢ Watch a customer's domains    ▸ │ │
│ │ ⌕ DNS Lookup     example.com    10:47            │ └───────────────────────────────────┘ │
│ └──────────────────────────────────────────────────┘ ┌ This workspace ───────────────────┐ │
│                                                      │ 12 servers · 2 expected CAs        │ │
│                                                      │ "Renewals every March…"   Manage ▸ │ │
│                                                      └────────────────────────────────────┘ │
│ (lock) Home reads only what this browser keeps; it sends nothing.                          │
└───────────────────────────────────────────────────────────────────────────────────────────┘

PHONE 375 — the same cards stacked: quick start, Needs attention, Recent domains (name + time;
the quick actions behind a "⋯" per row), Results in this tab, Start a job (two columns of chips,
as the start picker today), This workspace.
```

The quick start is the palette's combobox, rendered inline: the same parser, actions and keyboard
model as Ctrl K. It carries `data-shortcut="focus"`, so `/` reaches it. ui/palette.js and
lib/palette.js load on the field's first focus or keystroke, as they do for Ctrl K today, so they
stay off the start route.

Grid: `display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); gap: var(--space-6)`
from 1100 px; one column below. All cards use `Card` with `--card-pad`. Rows inside cards are 36 px.

### 4.4 Empty state: first run, or a new workspace

Shown when the workspace has no recent domains, no CT baseline, no registration snapshot, no
waivers and no servers.

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ Default workspace                                                                          │
│ Everything runs in this browser. Nothing is sent until you run a tool.                     │
│ ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ⌕  Domain, host name, IP address, network or AS number — or paste a PEM certificate    │ │
│ └───────────────────────────────────────────────────────────────────────────────────────┘ │
│ Start a job                                                                                │
│ [◫ Find every subdomain] [◎ Where must this certificate go?] [∿ Check a domain's health]  │
│ [⊕ Is my DNS change live everywhere?] [▤ Import a zone file] [▢ Watch a customer's domains]│
│ Set up this workspace (optional)                                                           │
│ ○ Add your servers — tools then name the machine behind each IP.              Servers ▸   │
│ ○ Name the CAs you use — other issuers get flagged.                           Workspaces ▸│
│ ○ Check your domains once in Domain portfolio — their expiry dates then show here. Open ▸ │
│ ○ Keep one workspace per customer.                                            New ▸       │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

- Each checklist item gets a ✓ once its data exists: a server saved; an expected CA named; an
  `rdapSeen` entry; a second workspace, or this one renamed from Default. The checklist hides when
  all four are done, or when the user hides it (`state.settings.homeSetup = false`, a new global
  setting next to `startTasks`).
- The *Start a job* cards stay on Home for good, folded to a compact list once there is data.
  This replaces the first-visit strip on the Subdomains page; `state.settings.startTasks` keeps
  only the *expanded* state.
- About › Where to start keeps the same `StartTaskList`.

---

## 5. Page template

### 5.1 Regions

Every tool renders the same regions in this order. The class names are new shared classes in
style.css. Existing view classes stay on the same elements as extra hooks (§8, selector policy).

Regions 6–8 belong to the data they count. In a tool with tabs they sit inside the active tab's
panel, so each tab carries its own figures, findings and toolbar. Today, Portfolio's seven tiles
count only its Domains tab, and SSL Targets' tiles and alerts only its Hosts tab. The first draft's
fixed order (metric strip, then findings, then tabs) would have shown them above the tabs they do
not describe.

```
┌ 1 .page-header ─────────────────────────────────────────────────────────────────────────────┐
│ [◫] Domain Health                                                                     [ⓘ]  │ icon 28px, h1 --fs-xl
│     NS, SOA, MX, SPF, DMARC, DKIM, CAA, DNSSEC and registration checks.                     │ .page-purpose, 1 line
└─────────────────────────────────────────────────────────────────────────────────────────────┘
┌ 2 .tool-input (card) ───────────────────────────────────────────────────────────────────────┐
│ .tool-input-fields   [example.com………………………………………………………………]  [▶ Check health] ← 3 .run-bar   │
│ .tool-input-extras   Try (example.com) (github.com) (cloudflare.com)    Options: 8 selectors ▸│
│ .tool-input-foot     (lock) Sends DNS questions to your DoH resolvers and one RDAP lookup.    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
┌ 4 .result-head (card) ──────────────────────────────────────────────────────────────────────┐
│ ⚠ Needs attention · example.com                                                B  89/100    │ .result-title + .result-key
│ Checked 10:51 · zone example.com · 4 resolvers                                              │ .result-meta
│ ✕ 0 errors  ⚠ 2 warnings  ⓘ 8 notes  ✓ 14 passed    [Copy summary][¶][Report][Export▾][Copy link] │ .status-summary + .result-actions
│ Also check: ⌕ DNS Lookup · ⊕ Global DNS · ◎ SSL Targets                                      │ .result-related
└─────────────────────────────────────────────────────────────────────────────────────────────┘
  5 .result-tabs    Overview · Records 12 · Origins 2 · Problems 3 …   (text + count, no icons)
  ┄ in the active tab's panel, or right after region 4 in a tool without tabs:
  6 .metric-strip   DNS 100 │ Email security 100 │ Certificates & DNSSEC 85 │ Web 85 │ Registration 100
  7 .finding-list   (optional: replaces stacked alerts)
  8 .result-body    sections (h3 --fs-lg) · cards · TableToolbar + DataTable
```

| # | Region | Content rules |
|---|---|---|
| 1 | `.page-header` (shell, app.js `renderPageHeader`) | 28 px icon, H1 (`--fs-xl`/600) and **one** purpose line (`nav.<id>.purpose`, ≤ 80 chars, clamped to 2 lines on phones). The ⓘ button (`.page-about`, `aria-expanded`) opens a disclosure with the long `nav.<id>.desc` and a link to the tool's About section. `.page-actions` stays only for page-level actions; Copy link / Run again move to region 4. |
| 2 | `.tool-input` | **One** card. The primary field comes first and carries `data-shortcut="focus"`. Optional fields go in a grid; examples (`ExampleChips`) and the options summary (`OptionsDisclosure`) go in `.tool-input-extras`; the `PrivacyNote` goes in the footer. From the moment a run starts, the card gets `is-compact`. It becomes one row: the primary field, which stays an editable field; a one-line summary of the non-default options with `Edit` (`aria-expanded`), which unfolds the rest; and Run. Compacting at the start, not at the end, means nothing jumps while rows stream in. The Run/Stop button is the same element in both states, so focus stays on it. File tools use the same compact row ("2 reports loaded · Add files · Forget all"). |
| 3 | `.run-bar` | **The page's primary button**, with the play icon and the tool's verb ("Check health", "Look up", "Scan"). **At most one primary button is visible at a time.** Once a result is on screen, the compact row's Run turns secondary ("Run again"), and primary again as soon as the input changes. A tab that sends something of its own (Zone › Live check, Portfolio › Certificates (CT), SSL Targets › Verify) then shows its own run as the primary inside its panel, with its own `PrivacyNote`. Stop takes the same slot while running (`data-shortcut="cancel"`). It sits inline at the end of the primary row for single-field tools and right-aligned in `.tool-input-foot` for multi-field tools. On phones it is sticky at the bottom when the inline one is off-screen (generalised from SSL Targets' run bar). |
| 4 | `.result-head` | Present from the moment a run starts. **Title:** the verdict for verdict tools (status icon + words), else "<subject> — <what>" ("Subdomains of example.net"). **Key metric** at the right: grade/score, compliance %, days left. **`.result-meta`:** time, counts and resolver, plus the kept-result note "Result from 10:51 · Run again" (moved from the page header); while running, the progress line with a thin bar. **`.status-summary`** + **`.result-actions`** (§5.3), then the optional `.result-related` and `SourceChips` rows. |
| 5 | `.result-tabs` | `Tabs`, text and count only. Status-coloured counts for error/warn only. On phones they overflow-scroll with fade edges and a "more" chevron. The tab state goes in the URL as today (`tab=`). |
| 6 | `.metric-strip` | Optional. One row of label-over-value figures, 56 px tall. **Read-only.** A result filters in two places only: the status summary for severities (§5.4) and the TableToolbar's "Show" select for everything else. Today there are three (C12). Zeros fold into one sentence (IP Intel's `foldZeroStats`). |
| 7 | `.finding-list` | Optional. One card, one row per finding: icon, text, an optional action. It replaces stacked alerts. At most three rows show, then "n more". |
| 8 | `.result-body` | `Section` (h3 `--fs-lg` inside a result, so the outline reads tool → result → section), `Card`, `DataTable`, `KeyValueList`. Tables share `TableToolbar`: filter on the left, then a "Show" select, toggles, and the table's own CSV/JSON as icon buttons on the right. |

### 5.2 States

| State | Tool input | Result region |
|---|---|---|
| Empty | full | compact `EmptyState`, ≤ 120 px, no card: one line on what you get, plus 3–6 chips of what it checks. Never repeats the purpose line. |
| Shared link that waits for a click (Subdomains, Domain overview, Portfolio…; unchanged rules) | full, filled | `.result-head` in a *ready* state: "Ready to check example.com — nothing has been sent yet." + Run |
| Running | `is-compact` (the field disabled where it is today) | `.result-head` with a spinner icon, "Checking example.com…" and live meta; Stop in the run slot; rows stream in |
| Done | `is-compact` | full result; the sticky phone run bar hides |
| Partial / failed sources | `is-compact` | status summary adds "1 source failed — Retry" (existing `RetryButton`, `NaMark`); never a silent dash |
| Kept result (page session) | `is-compact`, filled | `.result-meta` shows "Result from 10:51 · Run again" |
| Error before any result | full | `ErrorBanner` in region 4's place |

### 5.3 Standard actions

There is one `ResultActions` component, in this fixed order, right-aligned in the result header:

| # | Action | Rule | Today |
|---|---|---|---|
| 1 | **Copy summary** (secondary, small) and **¶** (ghost icon button "Copy as plain text") | every tool with a result; adds the missing builders for Reverse DNS and Bulk Resolve (lib/summary.js) | `SummaryButton` in 16 tools; "Plain text" is a labelled ghost button. Keep `data-action="copy-summary"` and `"copy-summary-text"`. |
| 2 | **Report** | only where lib/report.js has a kind: Domain overview, Domain Health, DMARC (more later, see Appendix C) | `ReportButton` (3 tools) |
| 3 | **Export ▾** | menu button (`aria-haspopup="menu"`) listing the tool's files in today's order, then "Print / save as PDF" | 5–7 separate buttons; keep each item's `data-export` / `data-action` |
| 4 | **Copy link** | where the result has a permalink (`resultPermalink`); hidden for file results | page header in 10 tools |

**One file, no menu:** a tool with a single export (DNS Lookup's dig file, Monitoring's timeline
CSV) shows it as a plain button, not a one-item menu.

**Phone:** Copy summary stays, and the others go into a "⋯" menu.

**Tool-specific actions** ("Find servers for this certificate", "Explain", "DNSSEC chain", "Add names
to a scan", "Domains on these addresses"):

- They are *next steps*: a `NextSteps` row of ghost buttons with tool icons. It sits under the status
  summary when it concerns the whole result, or in the relevant tab.
- They never mix with the four standard actions.
- Destructive actions (Forget, Remove) go last in the ⋯ / Export menu tail, with their existing
  confirmations.

### 5.4 Status summary

`StatusSummary` renders up to five items as `icon count label`, ordered error → warn → info → ok →
neutral.

- Each tool maps its outcome onto these severities (§6.2); tools without severities show neutral
  counts.
- **The items are the result's severity filters.** Each is a `button` with `aria-pressed`, and its
  accessible name is its visible text ("2 warnings"). In a tool with tabs, pressing one opens the
  tab that lists those rows, with the filter applied.
- The summary is not a live region. One `announce()` says the totals when the run ends.
- Zero counts are left out, except the error count in verdict tools, where "0 errors" is the good
  news.

### 5.5 Variants

| Variant | Tools | Differences from the base template |
|---|---|---|
| Query | Domain overview, Health, Subdomains, Lookup, Global DNS, Renewal readiness, Retire an IP | base |
| Batch | Bulk Resolve, IP Intel, Reverse DNS, Portfolio | textarea input; metric strip + table are the body (Portfolio: per tab, below) |
| Wizard | SSL Targets | region 2 keeps the numbered steps (certificate, domains, servers, options) and the requirement line; the run bar is sticky at all widths, as today. Once a scan starts, the steps fold into one summary row: "Certificate `*.example.net` · RSA 2048 · Domains example.net · 4 servers · recommended options — Edit". Today they stay full height above the results. |
| File | Certificate, Zone File, Certificate estate, DMARC & TLS reports, Monitoring | region 2 is `FileInput` (drop zone, paste, samples, how-to); compact row after loading; no Copy link |
| Editor | Servers, DNS change request | output is live as you type; the run bar holds Save / "Read the current records"; the sub-pages (Servers: Inventory · Origin map · Exposure audit) are tabs right under the page header, above region 2 |
| Document | About | page header + "On this page" chips + sections; no regions 2–7 |
| Dashboard | Home | §4 |

**Tabs that are tools of their own.** In SSL Targets, Certificate, Zone File and Domain portfolio,
the tabs hold different data sets, and some send requests of their own: Verify, Live check, New
name servers, Certificates (CT). The rules for them:

- Each panel holds its own regions 6–8: metric strip, findings and toolbar.
- A panel that sends something has its own run row and `PrivacyNote`, with a quota line where the
  source has one (Cert Spotter's 10 an hour).
- The result header's status summary counts the whole result.

### 5.6 Mapping of the existing views

Status summary items use: ✕ error, ⚠ warn, ⓘ info, ✓ OK, · neutral.

| Tool (id) | Variant | Run label | Result title / key metric | Status summary | Standard actions | Next steps / related | Tabs | Today → change |
|---|---|---|---|---|---|---|---|---|
| Domain overview (`domain`) | Query | Build overview | `example.com` — overview · grade | ✕/⚠ from the health card · n/a cards | Copy summary, Report, Copy link | Also: Health · Lookup · Subdomains | — (cards grid) | `.dov-head` + page-header Copy link → result head; 260 px empty card → compact |
| Domain Health (`health`) | Query | Check health | verdict ("Needs attention") · grade + score | ✕ errors ⚠ warnings ⓘ notes ✓ passed | Copy summary, Report, Export (Report JSON, Print), Copy link | Also: Lookup · Global DNS · SSL Targets | — (sections; category scores in the metric strip) | `.hlt-hero` traffic light → status icon + verdict; 48 px gap → `--stack-gap` |
| Subdomains (`subdomains`) | Query | Scan | Subdomains of `example.net` | · hosts · resolving ⓘ behind CDN ⚠ not resolving ✕ sources failed | Copy summary, Export (names.txt, CSV, JSON), Copy link | Next: Find certificate targets · Bulk Resolve | Overview · Hosts · Origins · Sources | `.sub-hero` (19 px title, 48 px field, 3-line explainer) → `.tool-input`; "Where do the subdomains come from?" → EmptyState chips + About link; Run again/Copy link → result head; segmented filter → the status summary (not resolving, behind CDN) and the Hosts toolbar's Show select (kinds); kind counts in a read-only metric strip inside Hosts |
| DNS Lookup (`lookup`) | Query | Look up | `example.com` · answered by Cloudflare in 40 ms | · types · records · no records: … ✕ failed | Copy summary, Export (dig format), Copy link | Next: Explain · DNSSEC chain; Also: Global DNS · Health | — (record cards) | `.lkp-sum` → result head; 7 buttons → 4 standard + 2 next steps + 2 related |
| SSL Targets (`scan`) | Wizard | Start scan | Scan of `example.net` · servers to update | ⚠ servers to update · ✓ covered ⓘ behind CDN ⚠ not resolving | Copy summary, Export (Hosts CSV, Servers CSV, Full JSON, names.txt, targets.txt), Copy link | Next: Verify · Rollout | Hosts · Servers · Behind CDN · Verify · Rollout · DANE · Sources · CT certificates | progress card + stage chips → result meta; 7 tiles → metric strip and 6 alerts → finding list, both inside the Hosts tab; Verify keeps its own run and PrivacyNote (Globalping probes connect to your servers); the wizard folds to one summary row once a scan starts; table CSV/JSON → toolbar icons |
| Certificate (`cert`) | File | (Read certificate / Load) | CN (mono) · days left | ✕ expired / ⚠ ≤ 30 d · chain complete/incomplete · CAA | Copy summary, Export (PEM, full chain, copy PEM, Print), Copy link when loaded from a host name | Next: Find servers for this certificate · Renewal readiness | Names · Details · Chain · CAA · DANE/TLSA · CT logs · PEM & OpenSSL · Compare | 8-button `.cert-actions` → 4 + 2; "Certificate shown" select stays in the result head; drop tab icons |
| Renewal readiness (`renew`) | Query | Check readiness | verdict ("At least one name will fail") | ✕ will fail ⚠ with warnings ✓ ready | Copy summary, Export (CSV, JSON), Copy link | Next: HTTP-01 test (card in body) | — (one accordion per name) | `.rnw-hero` red alert-in-card → result head |
| Certificate estate (`estate`) | File | — (reads on drop) | Certificate estate · 9 certificates on 7 endpoints | ✕ expired ⚠ expiring · name conflicts · shared keys · weak | Copy summary, Export (CSV, Print) | — | Certificates · Name conflicts · Shared keys | green privacy alert → PrivacyNote; left-aligned actions → result head; expiry/kind chips → metric strip |
| DNS change request (`change`) | Editor | Read the current records | What changes: + TXT `_acme-challenge.example.com` | · added · changed · removed | Copy summary, Copy link (check page) | Next: Check propagation (Global DNS) | For the DNS admin · BIND · Route 53 · Cloudflare API · octoDNS · Terraform ×2 | floating actions → result head; `.chg-hero` → result head |
| Global DNS (`global`) | Query | Check worldwide | verdict ("Answers differ") | ⚠ differ ✕ SERVFAIL ⓘ by design · answered x/y | Copy summary, Export (IPs CSV/JSON), Copy link | Also: Lookup · Health | Answer groups · IP addresses · Resolvers & locations | warn alert + findings → verdict + finding list; 4 tiles → metric strip; stacked sections → tabs |
| Zone File (`zone`) | File | (Import) | Zone `example.com` · BIND | ✕ errors ⚠ warnings · names · proxied | Copy summary, Export (via Convert; Print), ⋯ Forget | Next steps cards (Overview tab) | Overview · Records · Origins & servers · Problems · Live check · New name servers · Compare · Convert | green alert → PrivacyNote; tiles → metric strip inside Overview; "Scan now" is Overview's primary while the compact Import row is secondary; Live check and New name servers keep their own runs and PrivacyNotes (the file never leaves, the names do) |
| Retire an IP (`retire`) | Query | Check references | verdict ("8 records break something once 192.0.2.10 is gone") | ✕ breaks mail ✕ breaks DNS · must change ⚠ cannot tell | Copy summary, Export (CSV, JSON), Copy link | Next: Find other names on the address | per domain, or none | the second tool "Compare the old and the new server" → sub-page `#/retire/compare` (the `sub` route mechanism exists) |
| IP Intel (`ip`) | Batch | Look up | 3 addresses (new title) | · networks · countries ⓘ behind CDN · in your servers · private | Copy summary, Export (CSV, JSON), Copy link | Next: Domains on these addresses | — | `.ipi-results-bar` (no title) → result head; hint alert → muted line; phone table → cards |
| Bulk Resolve (`bulk`) | Batch | Resolve | 8 host names resolved | · resolving ⓘ behind CDN · direct ⚠ not resolving · your servers | Copy summary (new), Export (CSV, JSON), Copy link (`names=`) | Next: Use in IP Intel | Host names · IP addresses | run button → under the list, right-aligned + sticky on phone; progress card → result meta; phone table → cards |
| Reverse DNS (`ptr`) | Batch | Sweep | Reverse DNS of `192.0.2.0/28` | · named ✓ confirmed ⚠ not confirmed · no PTR ✕ failed | Copy summary (new), Export (names.txt, CSV, JSON), Copy link | Next: Add names to a scan · Add to Servers | — | progress card → meta; toolbar unified |
| DMARC & TLS reports (`reports`) | File | — (reads on drop) | Reports for 2 domains; per domain the verdict ("Not ready for p=reject yet") · compliance % | ✕ failing · messages · senders | Copy summary, Report, Export (Print) | Next: Identify senders | DMARC · TLS-RPT (· History) | green alert → PrivacyNote; footer buttons → `FileInput`; drop tab icons |
| Domain portfolio (`portfolio`) | Batch | Check portfolio | Portfolio of 3 domains | ✕ expiring < 30 d · critical status ⚠ no transfer lock · NS domain at risk | Copy summary, Export (CSV, JSON, Calendar .ics), Copy link | — | Domains · Domain security · Policy audit · Certificates (CT) | `.pf-head` → result head; 7 tiles → metric strip inside the Domains tab (they count only its rows); Certificates (CT) keeps its own run, Cert Spotter quota line and PrivacyNote; privacy text moves under the run bar |
| Monitoring (`monitor`) | File | — (reads on drop / GitHub) | Nightly results · 5 targets · last night | ✕ bad changes ⚠ expiring · did not complete | Copy summary, Export (timeline CSV) | — | Targets · Changes (today stacked) | green alert → PrivacyNote; sections → tabs |
| Servers (`inventory`) | Editor | Save inventory | 6 servers | · IPs · groups ⚠ warnings | Export (targets.txt, CSV, JSON) | — | sub-page tabs: Inventory · Origin map · Exposure audit | tabs move under the page header and above the notice; green alert → PrivacyNote |
| About (`about`) | Document | — | — | — | — | — | — | hero kept, without the gradient; the *Where to start* cards = Home's `StartTaskList` |

---

## 6. Design tokens

All tokens live in `assets/css/style.css § 1`, as today. They are written once for light, again under
`@media screen and (prefers-color-scheme: dark) { :root:not([data-theme="light"]) }` and again under
`@media screen { :root[data-theme="dark"] }`, the same three-block pattern as today. Paper keeps the
light palette. **Existing token names keep their meaning**; new ones are added next to them.

**No token is renamed.** The first draft renamed some, and with no alias a `var()` that no longer
resolves unsets its property silently. They keep today's names:

- `--focus-halo` → today's `--focus-ring`;
- `--shadow-1` → `--shadow-sm` (cards; `--shadow-xs` stays for buttons);
- `--shadow-2` → `--shadow` (menus, sticky bars);
- `--shadow-3` → `--shadow-lg` (dialogs).

These names are used 24 times today: 13 in style.css, 11 in the view stylesheets and palette.css.
The set below uses them.

### 6.1 The set

```css
:root {
  color-scheme: light;

  /* Fonts — system stacks only (no web fonts; the CSP has no font-src). Linux names added. */
  --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Liberation Sans", Arial, sans-serif,
    "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji";
  --font-mono: ui-monospace, "SFMono-Regular", "SF Mono", "Cascadia Mono", "Segoe UI Mono", Menlo, Consolas,
    "DejaVu Sans Mono", "Liberation Mono", monospace;

  /* Type scale: size / line height (px) */
  --fs-2xs: 11px;  --lh-2xs: 16px;   /* tags, kbd, nav group labels on short screens */
  --fs-xs: 12px;   --lh-xs: 16px;    /* meta, hints, timestamps, table second lines */
  --fs-sm: 13px;   --lh-sm: 20px;    /* controls, tabs, table cells, nav links */
  --fs-md: 14px;   --lh-md: 22px;    /* body copy, inputs, card titles */
  --fs-lg: 16px;   --lh-lg: 24px;    /* result title, section titles */
  --fs-xl: 20px;   --lh-xl: 28px;    /* page title, metric values */
  --fs-2xl: 28px;  --lh-2xl: 32px;   /* score (Health), compliance % */
  --fw-regular: 400; --fw-medium: 500; --fw-semibold: 600; --fw-bold: 700;

  /* Spacing: 4 px grid */
  --space-0-5: 2px; --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px;
  --space-5: 20px; --space-6: 24px; --space-8: 32px; --space-10: 40px; --space-12: 48px;

  /* Radii */
  --radius-xs: 4px;     /* tags, kbd, code, table row hover */
  --radius-sm: 6px;     /* buttons, inputs, selects, tabs' hover */
  --radius: 8px;        /* menus, popovers, inner panels, toasts */
  --radius-lg: 10px;    /* cards, dialogs (was 12px) */
  --radius-pill: 999px; /* chips (interactive), switches, progress */

  /* Density — comfortable (default) */
  --field-h: 36px; --btn-h: 32px; --btn-h-sm: 28px; --btn-h-lg: 40px;
  --row-h: 36px; --cell-x: 12px; --card-pad: 16px; --stack-gap: 20px; --section-gap: 32px;

  /* Layout */
  --header-h: 52px; --sidebar-w: 232px; --drawer-w: 280px; --content-max: 1360px;
  --page-x: 32px; --page-top: 20px; --page-x-phone: 16px;

  /* Focus */
  --focus-w: 2px; --focus-offset: 2px;

  /* Motion and layers */
  --dur: 140ms; --ease: cubic-bezier(0.2, 0.7, 0.2, 1);
  --z-sticky: 30; --z-header: 40; --z-popover: 60; --z-toast: 80;

  /* Colour roles — light */
  --bg: #f4f5f7;  --bg-sidebar: #f9fafb;
  --surface: #ffffff;  --surface-2: #f6f7f9;  --surface-3: #eceef2;  --surface-hover: #f2f4f7;
  --surface-selected: #e6e9ee;   /* neutral: selected nav item, pressed filter (K2); text-3 on it 4.62:1 */
  --border: #e2e5ea;  --border-strong: #cdd2da;
  --border-control: #858e9d;     /* fields, switch track, segmented outline: ≥ 3:1 on bg, surface, surface-2 */
  --text: #14171c;  --text-2: #464d5b;  --text-3: #5f6877;   /* text-3 was #687080 (4.29:1 on surface-3) */
  --text-disabled: #9aa1ad;  --on-accent: #ffffff;

  --accent: #2563eb;  --accent-hover: #1d4fd7;  --accent-solid: #2563eb;  --accent-solid-hover: #1d4fd7;
  --accent-soft: #edf3ff;  --accent-soft-border: #cadbfd;  --accent-text: #1d4ed8;
  /* --accent / --accent-hover: links, icons, bars. --accent-solid(-hover): fills under white text. */

  --ok: #157a3d;    --ok-solid: #16a34a;    --ok-bg: #ebf7ef;    --ok-border: #bfe4cb;
  --info: #1d4ed8;  --info-solid: #2563eb;  --info-bg: #edf3ff;  --info-border: #cadbfd;
  --warn: #975a06;  --warn-solid: #d97706;  --warn-bg: #fdf5e6;  --warn-border: #f1d9a8;
  --error: #b9232a; --error-solid: #dc2626; --error-bg: #fdeeee; --error-border: #f4c4c6;
  --neutral: #464d5b; --neutral-bg: #eceef2; --neutral-border: #e2e5ea;   /* facts with no judgement */
  --running: var(--accent);
  /* --k-* classification kinds: unchanged values; used by KindBadge and nothing else */

  --focus: #2563eb;  --focus-ring: 0 0 0 3px rgba(37, 99, 235, 0.25);
  --selection: rgba(37, 99, 235, 0.18);
  --shadow-xs: 0 1px 1px rgba(16, 24, 40, 0.04);                                       /* buttons */
  --shadow-sm: 0 1px 2px rgba(16, 24, 40, 0.05);                                       /* cards */
  --shadow: 0 4px 12px rgba(16, 24, 40, 0.08), 0 1px 3px rgba(16, 24, 40, 0.05);       /* menus, sticky bars */
  --shadow-lg: 0 18px 44px rgba(16, 24, 40, 0.16), 0 4px 12px rgba(16, 24, 40, 0.08);  /* dialogs */
  --backdrop: rgba(12, 16, 23, 0.46);
  --header-bg: rgba(255, 255, 255, 0.86);
}

/* Dark (written twice, as today) */
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0d1015;  --bg-sidebar: #10141a;
  --surface: #151a21;  --surface-2: #1a2028;  --surface-3: #242b35;  --surface-hover: #1d242d;
  --surface-selected: rgba(255, 255, 255, 0.07);
  --border: #28303b;  --border-strong: #3a4351;  --border-control: #646d7c;
  --text: #e6e9ef;  --text-2: #b3bbc8;  --text-3: #8c95a4;  --text-disabled: #5d6573;  --on-accent: #ffffff;
  --accent: #5b93ff;  --accent-hover: #7aa7ff;  --accent-solid: #2f6bdc;  --accent-solid-hover: #2a5fc6;
  --accent-soft: rgba(91, 147, 255, 0.13);  --accent-soft-border: rgba(91, 147, 255, 0.34);  --accent-text: #90b6ff;
  --ok: #62d394;    --ok-solid: #2fb468;    --ok-bg: rgba(47, 180, 104, 0.13);   --ok-border: rgba(47, 180, 104, 0.34);
  --info: #90b6ff;  --info-solid: #5b93ff;  --info-bg: rgba(91, 147, 255, 0.13);  --info-border: rgba(91, 147, 255, 0.34);
  --warn: #f2bb5b;  --warn-solid: #e6a23c;  --warn-bg: rgba(230, 162, 60, 0.13);  --warn-border: rgba(230, 162, 60, 0.34);
  --error: #ff8a8a; --error-solid: #ef4d4d; --error-bg: rgba(239, 77, 77, 0.13);  --error-border: rgba(239, 77, 77, 0.36);
  --neutral: #b3bbc8; --neutral-bg: #242b35; --neutral-border: #3a4351;
  --focus: #7aa7ff;  --focus-ring: 0 0 0 3px rgba(122, 167, 255, 0.32);
  --selection: rgba(91, 147, 255, 0.3);
  --shadow-xs: none;  --shadow-sm: none;                                  /* borders carry depth in dark */
  --shadow: 0 6px 16px rgba(0, 0, 0, 0.45), 0 1px 3px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 20px 48px rgba(0, 0, 0, 0.6), 0 4px 12px rgba(0, 0, 0, 0.35);
  --backdrop: rgba(0, 0, 0, 0.6);
  --header-bg: rgba(21, 26, 33, 0.86);
}

/* Density: compact (Settings › Density; never on touch screens) */
:root[data-density="compact"] {
  --field-h: 32px; --btn-h: 28px; --btn-h-sm: 24px; --row-h: 30px;
  --card-pad: 12px; --stack-gap: 16px; --section-gap: 24px; --page-x: 24px;
}

/* Touch: targets ≥ 40 px whatever the density. The compact selector is listed too: it is more
   specific than :root, so without it compact would win on a touch screen. */
@media (pointer: coarse) {
  :root, :root[data-density="compact"] { --field-h: 44px; --btn-h: 40px; --btn-h-sm: 36px; --row-h: 44px; }
}
```

**Contrast**, measured with the WCAG 2 formula:

- **Text:** every text role is ≥ 4.5:1 on `--surface`, `--surface-2` and `--bg` in both themes.
  The new `--text-3` reaches 4.84:1 on `--surface-3` (dark: 4.72:1).
- **Status text on its own tint:** ok 4.91, warn 5.13, error 5.59, info 6.02 (light); 6.7 or more
  (dark).
- **Button labels:** white on `--accent-solid` is 5.17:1 (light) and 4.93:1 (dark). On
  `--accent-solid-hover` it is 6.66:1 and 5.91:1; today's dark hover literal `#3b78ea` gives 4.15:1
  and goes. White on dark `--accent` (#5b93ff) is only 2.97:1, so a white label never sits on
  `--accent` or `--accent-hover`.
- **Controls (WCAG 1.4.11):** `--border-control` is ≥ 3:1 on `--bg`, `--bg-sidebar`, `--surface`
  and `--surface-2` in both themes (3.03–3.65:1). A control never sits on `--surface-3`, where it
  would be 2.85:1 (light) and 2.73:1 (dark). Today's field border is 1.52:1, and the switch's
  white thumb on its `--surface-3` track is 1.17:1. Fields, segmented outlines and the switch's
  off track take `--border-control` as their border, and the off thumb gets a 1 px ring of it.
  Native checkboxes and radios keep the browser's own border.
- **Links in running text** use `--accent-text`: light `--accent` is 4.45:1 on `--surface-3`.

### 6.2 Status colours and where they may appear

| Severity | Meaning | Text / icon | Tag & alert fill | Icon (always shown) | Examples |
|---|---|---|---|---|---|
| error | breaks now or will fail | `--error` | `--error-bg` / `--error-border` | `x-circle` | expired; will fail to renew; SERVFAIL; NS domain not registered |
| warn | risky or soon | `--warn` | `--warn-bg` / `--warn-border` | `alert` | expires within the warn band; no transfer lock; answers differ |
| info | worth knowing, no action implied | `--info` | `--info-bg` / `--info-border` | `info` | behind a CDN; not in your servers |
| ok | checked and fine | `--ok` | `--ok-bg` / `--ok-border` | `check-circle` | forward-confirmed; DNSSEC validated; ready |
| neutral | a fact | `--neutral` | `--neutral-bg` / `--neutral-border` | none | found by wordlist; self-signed (as a fact); RSA 2048 |
| running | in progress | `--running` | `--accent-soft` | spinner / ring | scan at 45 % |

Rules:

- **Stat tiles and metrics carry colour only on the value of an error or warn metric.** No more
  stripes keyed to classification kinds.
- **The `--k-*` palette is for `KindBadge` only:** Cloudflare, CDN, platform, direct, private,
  unresolved, NXDOMAIN, dangling.
- **Privacy notes are neutral** (lock icon, `--text-2`). `.sub-origin[data-tech="dns"]` becomes
  neutral too.
- **Solid fills carry no text.** `--ok-solid`, `--warn-solid` and dark `--error-solid` are 2.2–3.6:1
  against white, so they are only for icons, dots, bars and progress. A count on a status colour
  uses the tint (`--*-bg`) with the status text colour.
- **Selection is neutral, interaction is blue, information is blue with an icon.** The selected nav
  link and a pressed filter use the neutral `--surface-selected` with an accent bar or underline.
  The accent fill is for buttons, and `--info` always comes with its icon. This removes most of
  K2's overlap without a new hue: teal, orange and violet already belong to `--k-*`.
- **A table row shows its worst severity once**, as a 3 px inset bar on the row's leading edge
  (today's `.pf-table` / `.estate-table` left border, generalised as `.dt-row[data-severity]`).
  Inside its cells, only the cell that causes it is coloured; the other facts use neutral tags.
- **Expiry bands live in one place**, `lib/expiry.js` (new, DOM-free). It returns the severity for
  a kind and a number of days, and every view's days-left tag uses it:

| Object | error | warn | neutral/ok |
|---|---|---|---|
| Domain registration (Portfolio, Domain overview, Health, Home) | expired or < 30 days | < 60 days | later |
| Certificate (Certificate, Estate, Monitoring, CT watch, Home) | expired or < 7 days | < 30 days *(Monitoring uses 21 today; decision C1 in Appendix C)* | later |

### 6.3 Type: which size where

| Element | Token | Weight | Colour |
|---|---|---|---|
| Page title (h1) | `--fs-xl` | 600 | `--text` |
| Purpose line | `--fs-sm` | 400 | `--text-2` |
| Result title (h2) | `--fs-lg` | 600 | `--text` (the verdict's colour is on its icon only) |
| Section title (h3 inside a result, h2 elsewhere) / sub-section (one level down) | `--fs-lg` / `--fs-md` | 600 | `--text` |
| Card title | `--fs-md` | 600 | `--text` |
| Body copy, inputs | `--fs-md` | 400 | `--text`, `--text-2` |
| Buttons, tabs, nav links, table cells | `--fs-sm` | 500 (buttons, tabs, links), 400 (cells) | — |
| Meta, hints, table second lines | `--fs-xs` | 400 | `--text-3` |
| Tags, kbd, short-screen group labels | `--fs-2xs` | 600 | per tag |
| Metric value | `--fs-xl` | 600, `tabular-nums` | `--text`; `--error`/`--warn` for those metrics |
| Score / key metric | `--fs-2xl` | 700, `tabular-nums` | `--text` |
| Data: names, IPs, records, serials | mono at the size of its context (13 px in tables) | 400 | `--text` |

Migration of today's values:

| Today | Becomes |
|---|---|
| 10.5 / 11 / 11.5 px | `--fs-2xs` |
| 12 / 12.5 px | `--fs-xs` |
| 13 / 13.5 px | `--fs-sm` |
| 14 / 14.5 px | `--fs-md` |
| 15–17 px | `--fs-lg` |
| 18–23 px | `--fs-xl` |
| ≥ 24 px | `--fs-2xl` (score only) |
| weights 550 / 650 | 500 / 600 |

**Linux fonts:** the CI runs the e2e suites with Linux fonts (DejaVu / Liberation), which set wider
than Segoe UI or SF. So no label may depend on fitting a fixed width: labels wrap, and only values
truncate, with a `title`. Re-check at 320 and 375 px in every phase. DejaVu and Liberation have no
500 face either, so 500 renders as 400 there. No state may hang on a 400 → 500 change: active and
selected states use colour, background and a bar. 600 is safe, since it renders bold.

**Times:** a relative time ("2 h ago", "Result from 10:51") is a `<time datetime>` element. Its
`title` gives the absolute local time with the UTC offset, so an engineer can match it against a
log.

### 6.4 Spacing

| Today | Becomes |
|---|---|
| 1–3 px | `--space-0-5` |
| 4–6 px | `--space-1` |
| 7–10 px | `--space-2` |
| 11–14 px | `--space-3` |
| 15–18 px | `--space-4` |
| 19–22 px | `--space-5` |
| 24–28 px | `--space-6` |
| 30–36 px | `--space-8` |
| ≥ 40 px | `--space-10` / `--space-12` |

Layout rhythm:

- page top: `--page-top`;
- between regions: `--stack-gap` (20 px), the same everywhere;
- between sections in the body: `--section-gap`;
- inside cards: `--card-pad`;
- between inline controls: `--space-2`.

### 6.5 Elevation, radii and focus

- **Elevation.** Cards are flat: a `--border` with `--shadow-sm`, and no shadow in dark.
  `--shadow` is only for things that float (menus, the sticky run bar, the drawer) and `--shadow-lg`
  only for dialogs. No card nests inside another card; the one exception is a `DataTable` frame.
- **Radii** follow §6.1.
- **Shapes.** Interactive chips are pills. Static tags are 4 px rectangles. This is what tells a
  filter chip from a status tag.
- **Focus.** Every focusable element gets `outline: var(--focus-w) solid var(--focus);
  outline-offset: var(--focus-offset)` on `:focus-visible`. Fields add `box-shadow:
  var(--focus-ring)` and `border-color: var(--focus)`. Headings that receive programmatic focus
  (`#page-title`, `.result-title`) show the ring only on `:focus-visible`. Today several stylesheets
  repeat that rule (`.zone-summary-title`, `.rpt-results-title`, `.sub-org-title`,
  `.zcmp-other-title`); the shared `.result-title` class replaces those copies.
- **Forced colours** (`@media (forced-colors: active)`) drop background fills. So the selected nav
  link, a pressed filter, the current tab and the row severity bar also get a border or outline in
  `Highlight` / `CanvasText`, and tags keep their 1 px border. Focus rings are outlines, which
  forced colours keep.

### 6.6 Density

- **Comfortable is the default.** Settings gets *Density: Comfortable / Compact*. It sets
  `data-density` on `<html>` (boot.js applies it before first paint, like the theme). The setting
  is global, not per workspace.
- **Compact** shrinks fields, buttons, rows, card padding and gaps (§6.1). It never applies on
  `pointer: coarse`.
- **Not touched by density:** type sizes, the sidebar height tiers, and the `24 px` minimum link
  target that the shell e2e asserts.

---

## 7. Component inventory

Keep = unchanged API and look, apart from tokens. Change = same API, new look or rules. Merge = replace
several per-view patterns. New = add to a new module, `assets/js/ui/template.js`, unless noted;
its styles go in style.css § 4. The views import it statically, so it loads with the first tool,
never with Home. ui/components.js is on the start route (31.8 KB of the 244.9 KB that the start
route carries before any view), and the result template serves only the tools. `Tag`/`Chip` go
in components.js, because Home and the shell use them.

| Component | Today | Decision | Target look and rules |
|---|---|---|---|
| `Icon` | 74 icons | Keep | add `home`, `more` (⋯); the run button always uses `play`, Stop uses `stop` |
| `Button`, `IconButton`, `ButtonLink` | 34 px md, 28 sm, 40 lg | Change | heights from `--btn-h*`; 13 px/500 labels; **one primary per region** (region 3 owns the page's primary) |
| `CopyButton`, `ExternalLink` | — | Keep | — |
| `Badge` | one pill for everything | **Change → `Tag` + `Chip`** | `Tag` (static): 4 px radius, `--fs-2xs`/600, 20 px tall, severity or neutral fill, optional icon. `Chip` (interactive): pill, 28 px, `aria-pressed` for filters. `Badge()` stays as an alias that renders a `Tag`, so callers do not change in phase 1. |
| `KindBadge` | pill with kind colours | Change | a `Tag` with `--k-*` colours; the only user of that palette |
| `SeverityIcon`, `SeverityBadge` | — | Keep | used by `StatusSummary` |
| `Alert`, `ErrorBanner` | 4 variants, used for layout too | Change | rules: at most one alert per region; `ok` + lock is not a privacy note any more; hints become muted text; compact is the default inside cards |
| `EmptyState` | 52 px icon, 40 px padding; 8 per-view wrappers | Change + merge | compact by default (32 px icon, ≤ 120 px), no surrounding card; optional `checks: string[]` renders "What it checks" chips |
| `Section` | — | Keep | h2 `--fs-lg`; `--section-gap` between sections |
| `Card` | 12 px radius, shadow | Change | 10 px radius, `--shadow-sm`, 44 px head, `--fs-md`/600 title, 28 px icon box only in Home and FileInput |
| `StatCard` | 90–110 px tile with a coloured stripe; 11 per-view grids | **Merge → `MetricStrip`** | one row of `Metric`s (label `--fs-xs` above value `--fs-xl`), 56 px; dividers instead of boxes; read-only (severity filters live in `StatusSummary`, the rest in the toolbar's Show select, §5.1); zero metrics folded into one sentence; phones: 2 columns, 48 px each, or one scrolling row. `StatCard()` stays as an adapter during phases 2–6. |
| `KeyValueList`, `CodeBlock`, `CliText`, `TruncatedList`, `Disclosure` | — | Keep | tokens only |
| `Toolbar` | free-form | Change → `TableToolbar` | filter on the left (≤ 320 px), the "Show" select, toggles, then the table's CSV/JSON as icon buttons on the right; one row on desktop, two on phones |
| `Tabs` | icons in 6 views | Change | text + count; no icons; status-coloured count for error/warn only; overflow fade + chevron on phones |
| `SegmentedControl` | — | Keep | stays for modes (Files / GitHub, English / Türkçe, shells); no longer used as a table filter |
| `toast`, `Modal`, `confirmDialog` | — | Keep | `Modal` gets a `sheet` size (the phone Tools sheet, which hosts the palette's box, and the tablet drawer) |
| `FileDrop` | full drop zone always | Change → part of `FileInput` | after loading: one row "2 reports loaded · Add files · Forget all"; samples and how-to inside `FileInput` |
| `textInput`, `textarea`, `select`, `checkbox`, `radioGroup`, `checkboxGroup` | 36 px fields | Keep | heights from `--field-h` |
| `DataTable` | shared; card mode on phones in some views | Change | rows `--row-h`; `.dt-row[data-severity]` bar; one footer string, "Showing {shown} of {total}"; **card mode on phones for every table** (Bulk, IP Intel and Lookup's record tables adopt it) |
| `ProgressBar`, `Spinner` | progress cards | Change | inside `.result-meta` while running; gone when done |
| `SummaryButton` (ui/summary-button.js) | 16 tools | Change | becomes action 1 of `ResultActions`; "Plain text" becomes the ¶ icon button with the same `data-action` |
| `ReportButton` (ui/report-button.js) | 3 tools | Keep | action 2 of `ResultActions` |
| `TargetChip`, `KeptNote` (ui/session-ui.js) | header chip; note in the page header | Change | the chip stays in the desktop header and moves into the Tools sheet on phones; `KeptNote` moves into `.result-meta` |
| `SourceChip`, `NaMark`, `RetryButton` (ui/source-status.js) | chips in 4 placements | Keep | one place: the `SourceChips` row of the result head |
| `StartTaskList` (ui/start-tasks.js) | first-visit strip + About | Change | Home's *Start a job* (6 tasks) and About; compact list variant |
| `WorkspaceSwitch`, `WorkspaceMenuEntry` (ui/workspace-ui.js) | name only | Change | name + server count from 1280 px |
| Per-view result headers: `.sub-run-head` `.dov-head` `.zone-summary` `.scan-results-head` `.cert-overview` `.rnw-hero` `.estate-overview` `.glb-summary` `.lkp-sum` `.chg-hero` `.ipi-results-bar` `.ptr-results` `.retire-head` `.hlt-hero` `.rpt-results-head` `.pf-head` `.mon-summary` | 17 | **Merge → `ResultHeader`** | §5.1 region 4; the old class stays on the element as a hook |
| Per-view stats `.*-stats` (11), empties `.*-empty` (8), actions `.*-actions` / `.*-exports` (15), heroes `.sub-hero` `.chg-hero` `.hlt-hero` `.rnw-hero` | — | **Merge** | `MetricStrip`, `EmptyState`, `ResultActions`, `ToolInput` |
| — | — | **New `PageHeader` purpose/ⓘ** (app.js) | §5.1 region 1 |
| — | — | **New `ToolInput`** | §5.1 region 2; `{ fields, extras, privacy, run, compactSummary }`; compact from the run's start, with the primary field still editable |
| — | — | **New `RunBar`** | generalises SSL Targets' sticky bar (scan.js / scan.css) with `IntersectionObserver`; Run/Stop share a slot; focus moves Run ⇄ Stop as today; carries the `scroll-padding-bottom` rule (`--scan-runbar-h` becomes `--run-bar-h`) |
| — | — | **New `ExampleChips`** | "Try" + `Chip`s in mono; fills the primary field and focuses Run (sends nothing) |
| — | — | **New `OptionsDisclosure`** | `Disclosure` with a one-line summary of non-default choices (generalises Subdomains / SSL Targets) |
| — | — | **New `PrivacyNote`** | lock icon + one line, `--fs-xs`, `--text-2`; optional "What is sent" link to About › What this page sent |
| — | — | **New `ResultHeader`, `StatusSummary`, `ResultActions`** | §5.1 region 4, §5.3, §5.4 |
| — | — | **New `MenuButton`** | for Export ▾ and ⋯: `popover="auto"` (light dismiss, Esc; the top layer, so no card clips it), positioned with CSSOM only (CSP-safe). Button: `aria-haspopup="menu"`, `aria-expanded`. Menu: `role="menu"` of `menuitem` buttons that keep their `data-export` / `data-action`; arrow keys, Home/End and type-ahead (roving focus). Esc and Tab close it, and focus goes back to the button. It also goes in components.js: Home's "⋯" per recent domain uses it |
| — | — | **New `FindingList`** | one card; rows `icon · text · action`; replaces stacked alerts |
| — | — | **New `NextSteps` / related row** | ghost buttons with tool icons; "Also check:" wording |
| — | — | **New `HomeCard`s** (views/home.js) | Needs attention rows (each row one link), Recent domains, Results in this tab, This workspace; the quick start is ui/palette.js's combobox inline, loaded on first focus |

---

## 8. Phased rollout

**Ground rules for every phase:**

- **Additive selectors.**
  - New shared classes are added *next to* existing ones, e.g. `class: ['hlt-hero', 'result-head']`.
    `data-action`, `data-role`, `data-control`, `data-tab`, `data-export` and `data-view` values
    never change.
  - When an element moves (Copy link from the page header to the result head), it takes its
    attributes with it.
  - Suites that read `.page-actions` (carry, health, ip, lookup, retire, subdomains) or click
    exports (via `page.click`) get two shared helpers in `tests/e2e/scan.e2e.mjs`:
    `openResultMenu(page)` and `resultAction(page, name)`. `page.click` is a real mouse click, so
    an item inside a closed menu cannot be clicked without them. 18 suites use `data-export`
    selectors today.
  - The phone bar keeps `[data-control="lang"] [data-value]`, `[data-control="settings"]` and
    `[data-control="nav-menu"]`. The Tools sheet stays a `dialog.navmenu-modal` with its
    `.navmenu-link[data-view]` tiles (§3.4).
- **CSP:**
  - no inline `style` or `<style>`, no `setAttribute('style')`; positions and sizes only through
    CSSOM (`el.style.top = …`), as today;
  - menus use `popover`, sheets and drawers use `<dialog>`;
  - no new origins; icons stay inline SVG built with `svg()`.
- **Start-route budget** (`tests/js/start-route.test.js`, 370 KB): record the new total in the test's
  history comment every phase. Per-view CSS must shrink as views move to shared components. The
  test's list of modules that must stay off the route (`HEAVY`) gains lib/homedigest.js,
  ui/template.js, ui/palette.js and lib/palette.js.
- **Accessibility:**
  - one h1 per page; region 4's title is an h2;
  - landmarks unchanged;
  - every colour paired with an icon and a word;
  - targets ≥ 24 px (≥ 40 px on touch);
  - `prefers-reduced-motion` respected (no fades, no smooth scroll);
  - the shortcuts keep working: Ctrl/⌘+Enter, Esc, `/`, `?`, Ctrl/⌘+K.
- **Every string ships in EN and TR** (`tests/js/i18n-coverage.test.js` and `locales.e2e` enforce
  key parity).
- **Exit check per phase:**
  - CI green: unit tests and the phase's e2e suites;
  - screenshots of the touched views at 1440, 375 and 320 px, light and dark, EN plus one TR set;
  - no horizontal page scroll (`assertNoHorizontalScroll`);
  - zero console errors and CSP violations;
  - one review per phase.

### Phase 1 — tokens, shell and Home, in three steps

Each step is its own PR with its own exit check. The first draft shipped all of it at once,
together with thirteen shared components that only Home would have used. One review would then have
covered every view's look, the whole shell and a new start page, and the result components would
have been designed before any of their callers.

**1a — tokens and base components.**

- Tokens §6.1 go in under today's names, and the base components switch to them: `Button`, fields
  and the switch (`--border-control`), `Card`, `Tabs`, the `Alert` rules, and `Badge()` → `Tag`
  (with `Chip`). This step also brings `--accent-solid-hover` and the coarse-pointer block, and
  boot.js sets `data-density`.
- Only style.css § 1–4, components.js and boot.js change. The view stylesheets are not touched:
  their own sizes and spacing move with their phase. Views move by ≤ 2 px (buttons 34 → 32 px,
  card radius 12 → 10 px), apart from the intended shape change of static badges (pill → 4 px tag).
- Exit check: every e2e suite, not only the touched ones, since every view uses these components.

**1b — shell and navigation.**

- The header (search button, no GitHub), the sidebar regrouped (§3.1), the tablet drawer, the phone
  bar and the Tools sheet with the palette's box (§3.4), and the page header's purpose line + ⓘ.
- Subdomains stays the start view in this step. Home's nav entry arrives with 1c.

**1c — Home.**

- New modules: views/home.js, css/views/home.css and lib/expiry.js; lib/homedigest.js (a dynamic
  import); and lib/regstatus.js, split out of lib/portfolio.js.
- Route and start page: `DEFAULT_VIEW = 'home'`, the start picker moves to Home, and `START_TASKS`
  gains `portfolio`.
- The three additive fields: lib/ctwatch.js `due` (ui/ctwatch-panel.js writes it), lib/rollout.js
  `total` (ui/rollout-panel.js writes it) and the `digests` part (lib/workspace.js; views/monitor.js
  writes it). Also ui/jobs.js `jobList()` and `startJob({ subject })`.

**Where the template components go:** `ResultHeader`, `StatusSummary`, `ResultActions`,
`MetricStrip`, `FindingList`, `PrivacyNote`, `ToolInput`, `RunBar`, `ExampleChips`,
`OptionsDisclosure` and `NextSteps` are built in phase 2, with their first four callers, in
ui/template.js. `Tag`/`Chip` (1a) and `MenuButton` (1c, for Home's "⋯") go in components.js.

**Files:**

- 1a: `assets/css/style.css` (§1 tokens, §4 components), `assets/js/ui/components.js`,
  `assets/js/boot.js`
- 1b: `assets/css/style.css` (§3 shell), `assets/js/app.js` (`VIEWS` order/groups,
  `renderHeaderActions`, `renderNav`, `openNavMenu`, `renderPageHeader`), `assets/js/lib/shellnav.js`
  (`NAV_GROUPS`), `ui/palette.js` (sheet mode), `ui/session-ui.js`, `ui/workspace-ui.js`,
  `assets/js/i18n.js` (groups, purpose lines)
- 1c: new `assets/css/views/home.css`, `assets/js/views/home.js`, `assets/js/lib/homedigest.js`,
  `assets/js/lib/expiry.js`, `assets/js/lib/regstatus.js`; `assets/js/app.js` (`DEFAULT_VIEW`,
  `VIEW_CSS_ORDER`, `startPicker` removal); `lib/shellnav.js` (`START_TASKS`); `lib/session.js`
  (`normalizeResult` keeps the optional `status`); `lib/portfolio.js` (re-exports);
  `lib/ctwatch.js` + `ui/ctwatch-panel.js`; `lib/rollout.js` + `ui/rollout-panel.js`;
  `lib/workspace.js`; `views/monitor.js`; `ui/jobs.js`; `ui/start-tasks.js`; `index.html` (brand
  `href`, the modulepreload list = app.js graph); `assets/js/i18n.js` (Appendix A)
- tests: `tests/js/start-route.test.js`, `shellnav.test.js`, `ui-dom.test.js`,
  `i18n-coverage.test.js`, `ctwatch.test.js` and `rollout.test.js` (the additive fields), the
  workspace tests (`digests`), new `homedigest.test.js` + `expiry.test.js`, new
  `tests/e2e/home.e2e.mjs` (seeds the workspace parts through `state`, asserts the cards, the "as
  of" rows and that Home sends nothing), `shell.e2e.mjs`, `subdomains.e2e.mjs`, `carry.e2e.mjs`,
  `locales.e2e.mjs`, `scan.e2e.mjs`, and the nav-group assertions of `change`, `domain`, `estate`,
  `monitor`, `portfolio`, `ptr`, `renew`, `reports`, `retire` and `zone` e2e.

**Risks:**

- **Start-route budget** (today 343,878 bytes: 244,853 of shell and 99,025 of Subdomains).
  - 1a and 1b keep Subdomains on the route: ≈ 350–355 KB, still under 370 KB.
  - 1c removes 99.0 KB: views/subdomains.js's graph beyond app.js (91.0 KB) and subdomains.css
    (8.0 KB). It adds ≈ 12–16 KB: home.js, lib/expiry.js, home.css, `MenuButton`, and Home's
    strings and the purpose lines in both languages.
  - Expected total: ≈ 260–270 KB against the 370 KB budget.
  - These stay off the route, and the test asserts it: lib/homedigest.js with the readers it
    imports, ui/template.js, ui/palette.js and lib/palette.js. The first draft counted
    lib/palette.js on the route and left out the 13 components it put in components.js.
  - The start-route test's `scanplan.js` / `sourceinfo.js` assertion moves to a "Subdomains view
    graph" test.
- **CSP:** `MenuButton` positioning via CSSOM only; no new external resources.
- **e2e:**
  - shell.e2e asserts the start picker above the Subdomains header, the 800 px nav strip, the
    phone Tools bar layout and `.nav-menu-current`'s text: all four are rewritten. Its assertion
    that the palette button is hidden on phones stays true;
  - the phone bar keeps `[data-control="lang"]`, `[data-control="settings"]` and
    `[data-control="nav-menu"]`, so the phone-width language switches (≈ 48 steps) and the five
    `deleteAllLocalData` helpers do not change;
  - subdomains.e2e asserts that the root lands on `#/subdomains`;
  - the 1366×657 "24 tools in view" check must still pass with Home counted. At ≤ 760 px each group
    keeps today's 4 px separator: 24 links × 24 px leave about 29 px of the sidebar's 605 px for
    separators and padding.
- **Users:**
  - bookmarks of the bare site URL now open Home, and Home's first job card is "Find every
    subdomain";
  - the dismissed-picker setting (`startTasks`) migrates to Home's folded state.

### Phase 2 — Investigate a domain (4 tools)

**Domain overview, Domain Health, Subdomains, DNS Lookup** move to the template:

- the result-template components are built here, in ui/template.js (new; the views import it, so
  it is never on the start route), and tested against these four callers;
- `ToolInput` with the compact state, `RunBar`, `ResultHeader`, `StatusSummary` (with its filters),
  `ResultActions`, `MetricStrip`, related links, the `EmptyState` with checks, and the Copy link /
  Run again move.

**Files:** new `assets/js/ui/template.js` (with its tests in `ui-dom.test.js`) and its styles in
style.css § 4; `assets/js/ui/summary-button.js` (the ¶ action);
`assets/js/views/domain.js`, `health.js`, `subdomains.js`, `lookup.js`;
`assets/js/ui/subdomains-run.js`, `ui/health-v2.js`, `ui/explain-panel.js`,
`ui/dnssec-panel.js` (placement only); `assets/css/views/domain.css`, `health.css`,
`subdomains.css`, `lookup.css`, `fix.css`; `assets/js/lib/summary.js` (no change expected);
e2e: `domain`, `health`, `subdomains`, `lookup`, `carry`, `explain`, `secscore`, `takeover`.

**Risks:**

- Hooks used in tests must stay: `.hlt-hero`, `.hlt-hero-domain`, `.sub-run-ui`, `.sub-run`,
  `.sub-table`, `.sub-tabs`, `.sub-org`, `.lkp-sum`, `.lkp-card`, `.dov-head`.
- Lookup's 480 px column-width assertion stays as long as the record cards keep their CSS columns.
- `tab=` in the Subdomains URL is unchanged.
- Start route: Subdomains left it in phase 1c, and ui/template.js stays off it. Only
  ui/summary-button.js, which is on it, changes, by a few hundred bytes.

### Phase 3 — Deploy & renew certificates (4 tools)

**SSL Targets, Certificate, Renewal readiness, Certificate estate.**

**Files:** `assets/js/views/scan.js`, `cert.js`, `renew.js`, `estate.js`; `assets/js/ui/verify-panel.js`,
`dane-panel.js`, `renewal-planner.js`, `rollout-panel.js`, `cert-diff-panel.js`, `chain-repair.js`,
`revocation-card.js`, `pfx-import.js`, `topology.js` (placement); `assets/css/views/scan.css`,
`cert.css`, `renew.css`, `estate.css`, `verify.css`, `dane.css`, `topology.css`;
e2e: `scan`, `cert`, `renew`, `renewal`, `estate`, `verify`, `dane`, `chainfix`, `pfx`, `revocation`,
`cutover`.

**Risks:**

- **SSL Targets' sticky run bar has detailed e2e checks** (focus, shadow, reduced motion, TR,
  375×667). `RunBar` must keep the class `scan-runbar` on SSL Targets and its behaviour.
- Hooks used in tests: `.scan-tab-verify` (54 uses), `.scan-run-ui`, `.scan-step-cert`,
  `.cert-tabs`, `.cert-overview-cn`, `.cert-summary`, `.cert-reload`.
- Exports move into the Export menu, so the shared helper is needed.

### Phase 4 — Change & migrate DNS (4 tools)

**DNS change request, Global DNS, Zone File, Retire an IP**, plus Retire's compare tool as
`#/retire/compare`.

**Files:** `assets/js/views/change.js`, `global.js`, `zone.js`, `retire.js`; `assets/js/ui/zone-tools.js`,
`fix-panel.js`, `cutover.js`, `origin-compare.js`, `isp-resolvers.js`, `parity-panel.js`,
`delegation-panel.js`; `assets/css/views/change.css`, `global.css`, `zone.css`, `zonetools.css`,
`retire.css`; e2e: `change`, `global`, `zone`, `retire`, `cutover`, `origins`, `dmarchistory`
(only if a link moves).

**Risks:**

- Moving Global DNS's sections into tabs changes the scroll positions that `global.e2e` reads
  (`.glb-summary`, `.glb-resolvers`). Keep the elements; only wrap them in tab panels.
- Splitting Retire's compare tool needs a redirect: the old in-page anchor opens
  `#/retire/compare`.
- `#/change/check` is unchanged.

### Phase 5 — Map IPs to servers + Workspace (5 tools)

**IP Intel, Bulk Resolve, Reverse DNS, Servers, About.** This phase adds the Copy summary builders
for Bulk Resolve and Reverse DNS, and DataTable card mode for every table.

**Files:** `assets/js/views/ip.js`, `bulk.js`, `ptr.js`, `inventory.js`, `about.js`;
`assets/js/ui/ip-enrich-panel.js`, `reverse-ip-panel.js`, `exposure-panel.js`,
`origin-map-panel.js`; `assets/js/lib/summary.js` + `lib/summarycore.js` (two new kinds);
`assets/css/views/ip.css`, `bulk.css`, `ptr.css`, `inventory.css`, `about.css`; e2e: `ip`, `bulk`,
`ptr`, `integration`, `privacy` (About ledger), `workspaces`.

**Risks:**

- `lib/summarycore.js` is on the start route. The two new builders go into lib/summary.js, which
  is lazy, as the start-route comment asks.
- `.ipi-row` and `.ipi-ip` hooks stay.
- About's "What this page sent" ledger must not change its numbers or its section ids
  (`#/about?section=sent`).

### Phase 6 — Watch & report (3 tools) and clean-up

**Domain portfolio, Monitoring, DMARC & TLS reports.** Then the clean-up:

- delete the dead per-view CSS (`.*-hero`, `.*-head`, `.*-stats`, `.*-empty` rules nothing uses);
- remove the `StatCard` / `Badge` adapters once no caller is left;
- add the Density setting to the Settings dialog;
- final contrast and phone pass.

**Files:** `assets/js/views/portfolio.js`, `monitor.js`, `reports.js`; `assets/js/ui/ctwatch-panel.js`,
`secscore-panel.js`, `renewal-panel.js`, `report-history.js`, `waivers.js`, `lookalike-panel.js`;
`assets/css/views/portfolio.css`, `monitor.css`, `reports.css`; `assets/css/style.css`
(adapter removal), the views' CSS (dead rules); e2e: `portfolio`, `monitor`, `reports`,
`dmarchistory`, `waivers`, `regwatch`, `secscore`.

**Risks:**

- `.pf-table`, `.pf-head`, `.rpt-sources`, `.rpt-spf`, `.rh-chart`, `.mon-table` are test hooks.
- Removing dead CSS can drop a rule that another view still needs, because several views share
  sheets (VIEWS[].css): `fix.css` (Zone File, DNS change request, Health), `cert.css` and `dane.css`
  (Certificate, Renewal readiness, SSL Targets), `subdomains.css` (Subdomains, SSL Targets). Delete
  per selector, with a grep of `assets/js` for each class.

---

## 9. What not to change

- **No framework, no build step, no dependencies, no third-party fonts or CDNs.** The CSP in
  `index.html` stays as it is.
- **Routes and parameters stay:** `#/<id>?…`, the view ids, the sub-pages (`#/change/check`),
  `run=0` / fill-only links, and which tools run on a shared link's arrival versus show a
  one-click prompt. That behaviour is a privacy and quota decision, not a layout one.
- **The hooks stay:** `data-action`, `data-role`, `data-control`, `data-tab`, `data-export`,
  `data-view`, `data-shortcut`, `data-shortcut-scope`, and the existing view-prefixed classes
  (new classes are added next to them).
- **The privacy model and its substance stay:**
  - what each tool sends and to whom stays stated next to its Run button;
  - the "What this page sent" ledger and the footer count stay;
  - texts get shorter on screen, with the full text one click away — never deleted.
- **The shell's behaviours stay:**
  - keyboard shortcuts;
  - focus moving to `#page-title` on route change, `announce()` on route change and on results;
  - the busy bar and job rings, the kept-result logic;
  - the current target and carry-over between tools;
  - offline notes, the service worker, the stale-module reload.
- **The data model stays:** workspaces, the page session, settings in `localStorage`, export
  formats (CSV with BOM, JSON, names.txt, targets.txt, .ics), the Copy summary text, and the report
  HTML. Home adds only the three additive fields of §4.2, which older readers ignore.
- **The brand stays:** accent blue, logo, classification colours (`--k-*`) and Global DNS's
  answer-group colours.
- **Behaviour inside the tables stays:** sorting, filtering, streaming rows, row details. Only the
  look and the phone card mode change.
- **The explanations stay.** Engineers use them; they move into ⓘ, disclosures and About.

---

## Appendix A — new strings (EN / TR)

All keys are registered in `assets/js/i18n.js` (shell) or in the owning module, in both languages.
"A / B" in the EN column is a plural object `{ one, other }` (i18n.js `plural`). Turkish does not
inflect a noun after a number, so the TR column has one form. TR strings use the typographic
apostrophe (’), as the app's strings already do ("DNS’te", "IP’leri").

| Key | EN | TR |
|---|---|---|
| `nav.home` | Home | Ana sayfa |
| `nav.home.purpose` | Your workspace at a glance: what needs attention and where to start. | Çalışma alanınıza bir bakış: ilgilenmeniz gerekenler ve nereden başlayacağınız. |
| `nav.groupInvestigate` | Investigate a domain | Alan adını incele |
| `nav.groupCerts` | Deploy & renew certificates | Sertifika kur ve yenile |
| `nav.groupChange` | Change & migrate DNS | DNS’i değiştir ve taşı |
| `nav.groupNetwork` | Map IPs to servers | IP’leri sunuculara eşle |
| `nav.groupWatch` | Watch & report | İzle ve raporla |
| `nav.groupSetup` | Setup & help | Kurulum ve yardım |
| `shell.search` | Search tools, domains, IPs… | Araç, alan adı, IP ara… |
| `shell.more` | More | Diğer |
| `shell.aboutTool` | About this tool | Bu araç hakkında |
| `shell.density` | Density | Yoğunluk |
| `shell.densityComfortable` | Comfortable | Rahat |
| `shell.densityCompact` | Compact | Sıkışık |
| `result.export` | Export | Dışa aktar |
| `result.print` | Print / save as PDF | Yazdır / PDF olarak kaydet |
| `result.plainTitle` | Copy as plain text | Düz metin olarak kopyala |
| `result.related` | Also check: | Ayrıca bakın: |
| `result.edit` | Edit | Düzenle |
| `result.ready` | Ready to check {subject} — nothing has been sent yet. | {subject} kontrole hazır — henüz hiçbir şey gönderilmedi. |
| `result.checking` | Checking {subject}… | {subject} kontrol ediliyor… |
| `result.sourcesFailed` | {count} source failed / {count} sources failed | {count} kaynak başarısız oldu |
| `table.showing` | Showing {shown} of {total} | {total} satırdan {shown} tanesi gösteriliyor |
| `home.titleDefault` | Default workspace | Varsayılan çalışma alanı |
| `home.facts` | {servers} servers · {recent} recent domains · last activity {when} | {servers} sunucu · {recent} son alan adı · son işlem {when} |
| `home.quick` | Domain, host name, IP address, network or AS number | Alan adı, host adı, IP adresi, ağ ya da AS numarası |
| `home.quickPem` | …or paste a PEM certificate | …ya da bir PEM sertifikası yapıştırın |
| `home.quickHint` | Opens the tool with it filled in; nothing is sent until you run it. | Aracı bu değerle doldurulmuş olarak açar; siz çalıştırana kadar hiçbir şey gönderilmez. |
| `home.attention` | Needs attention | İlgilenmeniz gerekenler |
| `home.attentionNone` | Nothing needs attention. | İlgilenmeniz gereken bir şey yok. |
| `home.certs` | {count} certificate expires within {days} days / {count} certificates expire within {days} days | {count} sertifikanın süresi {days} gün içinde doluyor |
| `home.reg` | Registration expires in {days} days | Kaydın bitmesine {days} gün kaldı |
| `home.regGone` | The registry does not know this domain | Kayıt kuruluşu bu alan adını tanımıyor |
| `home.regRisk` | Registry status: {status} | Kayıt durumu: {status} |
| `home.regNoLock` | No transfer lock | Transfer kilidi yok |
| `home.waivers` | {count} accepted risk ends within {days} days / {count} accepted risks end within {days} days | {count} kabul edilen riskin süresi {days} gün içinde doluyor |
| `home.waiversEnded` | {count} accepted risk has ended and counts again / {count} accepted risks have ended and count again | {count} kabul edilen riskin süresi doldu; yeniden sayılıyor |
| `home.rollout` | Rollout: {done} of {total} servers updated | Dağıtım: {total} sunucudan {done} tanesi güncellendi |
| `home.monitor` | Last night: {bad} bad changes on {targets} targets | Dün gece: {targets} hedefte {bad} kötü değişiklik |
| `home.stale` | last checked {when} | son kontrol {when} |
| `home.serversWarn` | {count} line in Servers could not be read / {count} lines in Servers could not be read | Sunucular listesindeki {count} satır okunamadı |
| `home.showAll` | Show all ({count}) | Tümünü göster ({count}) |
| `home.recent` | Recent domains | Son alan adları |
| `home.kept` | Results in this tab | Bu sekmedeki sonuçlar |
| `home.jobs` | Start a job | Bir işe başlayın |
| `home.workspace` | This workspace | Bu çalışma alanı |
| `home.manage` | Manage | Yönet |
| `home.setup` | Set up this workspace (optional) | Bu çalışma alanını hazırlayın (isteğe bağlı) |
| `home.setupServers` | Add your servers — tools then name the machine behind each IP. | Sunucularınızı ekleyin — araçlar her IP’nin arkasındaki makineyi adıyla gösterir. |
| `home.setupCas` | Name the CAs you use — other issuers get flagged. | Kullandığınız sertifika otoritelerini yazın — diğerleri işaretlenir. |
| `home.setupPortfolio` | Check your domains once in Domain portfolio — their expiry dates then show here. | Alan adlarınızı Alan adı portföyünde bir kez kontrol edin — bitiş tarihleri burada görünür. |
| `home.setupWorkspaces` | Keep one workspace per customer. | Her müşteri için ayrı bir çalışma alanı kullanın. |
| `home.setupHide` | Hide this list | Bu listeyi gizle |
| `home.privacy` | Home reads only what this browser keeps; it sends nothing. | Ana sayfa yalnızca bu tarayıcının sakladıklarını okur; hiçbir şey göndermez. |
| `home.loading` | Reading this workspace… | Bu çalışma alanı okunuyor… |
| `home.asOf` | as of {date} · Check again | {date} itibarıyla · Yeniden kontrol edin |
| `home.ctFirst` | CT: check once to see expiries here | CT: bitişleri burada görmek için bir kez kontrol edin |
| `home.regTransfer` | Transfer pending: {domain} | Transfer beklemede: {domain} |
| `home.rolloutTicked` | Rollout of {label}: {verified} verified, {installed} installed | {label} dağıtımı: {verified} doğrulandı, {installed} kuruldu |
| `home.dmarcLosing` | p=reject refuses mail of known senders: {domains} | p=reject bilinen göndericilerin e-postasını reddediyor: {domains} |
| `home.dmarcFixFirst` | Known senders fail DMARC: {domains} | Bilinen göndericiler DMARC’tan geçemiyor: {domains} |
| `home.more` | +{count} more | +{count} tane daha |
| `shell.toolsPrefix` | Tools: | Araçlar: |
| `start.task.portfolio` | Watch a customer's domains | Bir müşterinin alan adlarını izle |

Purpose lines (`nav.<id>.purpose`; the long `nav.<id>.desc` stays for ⓘ, the palette and About):

| Tool | EN | TR |
|---|---|---|
| subdomains | Find a domain's subdomains and where each one points. | Bir alan adının subdomain’lerini ve her birinin nereye işaret ettiğini bulun. |
| domain | One page per domain: registration, DNS, mail, web and certificates. | Alan adı başına tek sayfa: kayıt, DNS, e-posta, web ve sertifikalar. |
| zone | Import a zone export: every name, the real origins, mistakes and drift. | Zone dosyasını içe aktarın: tüm adlar, gerçek sunucular, hatalar ve farklar. |
| scan | Find every host, IP address and server a certificate must go on. | Bir sertifikanın kurulacağı her host’u, IP adresini ve sunucuyu bulun. |
| cert | Inspect a certificate: names, validity, key, chain, CAA and CT. | Sertifikayı inceleyin: adlar, geçerlilik, anahtar, zincir, CAA ve CT. |
| renew | Will the next ACME renewal validate? CAA, delegation, DNSSEC, HTTP-01. | Bir sonraki ACME yenilemesi doğrulanacak mı? CAA, devir, DNSSEC, HTTP-01. |
| estate | Read the CLI's estate reports: expiries, name conflicts, shared keys. | CLI’nin envanter raporlarını okuyun: bitişler, ad çakışmaları, ortak anahtarlar. |
| global | Compare answers from 12 resolvers and 30+ locations. | 12 çözümleyiciden ve 30’dan fazla konumdan gelen yanıtları karşılaştırın. |
| lookup | Query any record type, with DNSSEC status and the raw answer. | Her kayıt türünü DNSSEC durumu ve ham yanıtla sorgulayın. |
| bulk | Resolve hundreds of host names and match the IPs to your servers. | Yüzlerce host adını çözümleyin ve IP’leri sunucularınızla eşleştirin. |
| change | Write a DNS change once: for the admin, as BIND, API or Terraform. | DNS değişikliğini bir kez yazın: yöneticiye, BIND, API ya da Terraform olarak. |
| ip | Reverse DNS, network owner, location and CDN of IP addresses. | IP adreslerinin ters DNS’i, ağ sahibi, konumu ve CDN’i. |
| ptr | Sweep the reverse DNS of a network or an AS and confirm each name. | Bir ağın ya da AS’in ters DNS’ini tarayın ve her adı doğrulayın. |
| retire | Before an IP goes: every record, SPF and MX that still points at it. | Bir IP kapanmadan önce: onu hâlâ gösteren her kayıt, SPF ve MX. |
| health | NS, SOA, MX, SPF, DMARC, DKIM, CAA, DNSSEC and registration checks. | NS, SOA, MX, SPF, DMARC, DKIM, CAA, DNSSEC ve kayıt (whois) kontrolleri. |
| reports | Read DMARC and TLS-RPT reports: who sends as you and what fails. | DMARC ve TLS-RPT raporları: adınıza kim gönderiyor, ne başarısız oluyor. |
| portfolio | Many domains, one row each: expiry, registry flags, DNSSEC and mail. | Birçok alan adı, her biri tek satır: bitiş, kayıt işaretleri, DNSSEC, e-posta. |
| monitor | Open the nightly runner's results: trends, expiries and every change. | Gece çalışan kontrollerin sonuçları: eğilimler, bitişler ve her değişiklik. |
| inventory | Your server list: how every tool names the machine behind an IP. | Sunucu listeniz: her araç bir IP’nin arkasındaki makineyi buradan adlandırır. |
| about | How it works, data sources and quotas, privacy and the CLI. | Nasıl çalışır, veri kaynakları ve kotalar, gizlilik ve CLI. |

The old group keys (`nav.groupDiscover`, `nav.groupSsl`, `nav.groupDns`, `nav.groupIp`,
`nav.groupMail`, `nav.groupData`) are removed in phase 1. `nav.groupOther` stays for unknown groups.

---

## Appendix B — screenshots

**Where:** the audit's screenshots are in the session scratchpad,
`C:/Users/ibrahim/AppData/Local/Temp/claude/c--Users-ibrahim-Desktop-projects-domainscope/b8697ce5-6267-4879-85a2-b0a40ad0c29e/scratchpad/ui/`:

- `before/` holds the viewport shots;
- `before/full/` holds the full-page copies;
- `sheets/` holds the contact sheets.

The scripts that made them sit next to them: `shoot-empty.mjs`, `shoot-results.mjs`,
`shoot-shell.mjs`, `measure.mjs`, `shim.mjs` (loads a suite's private fakes without running it) and
`sheet.py`.

The screenshots are not committed, like `tests/e2e/screenshots/`. They were made against
`node tests/e2e/serve.mjs 8765` with `tests/e2e/cdp.mjs`. The result states use the suites' own
offline fakes:

| View | Fake |
|---|---|
| Domain Health | `zoneHandoffScript` with health's `MAIL_ZONE`, RDAP and Observatory fakes |
| Global DNS | `fakeGlobalDnsScript` |
| Domain portfolio | `fakeScript` |
| Retire an IP | `fakeScript(fakeTable())` |
| Reverse DNS | ptr's `fakeScript` |
| IP Intel | `IP_FAKE_SCRIPT` |
| Domain overview, Renewal readiness, DNS change request, DMARC & TLS reports | the suite's `fakeScript()` |
| Monitoring | `monitorFixture()` files |
| Certificate estate | `tests/fixtures/estate/report-*.json` |
| DMARC reports file | `tests/fixtures/mailreports/reports-2026-09.zip` |
| Zone File, Certificate | their bundled samples |
| Subdomains | `zoneHandoffScript('example.net', ZONE_HANDOFF_DNS)`, passive sources off, as subdomains.e2e does |
| SSL Targets | `zoneHandoffScript` with scan's `OFFLINE_DNS` and `tests/fixtures/ec_wildcard.pem` |
| DNS Lookup | `zoneHandoffScript('example.com', APEX_ZONE)` |
| Bulk Resolve | `zoneHandoffScript('example.net', …)` with eight names typed in |
| Servers | an inventory typed into the editor (not saved) |

To repeat the audit after a phase, re-run the same three steps (empty states, results, shell) with
the same names into `ui/after/`.

**What exists:**

- `<view>-desktop-{light,dark}-en-empty` and `<view>-phone-{light,dark}-en-empty` for all 20 views;
- TR empties for subdomains, health, scan, zone, portfolio, about (desktop light) and subdomains,
  health, scan, lookup (phone dark);
- `<view>-{desktop,phone}-{light,dark}-en-result[-at]` for 19 views (About: its ledger section);
- TR results for zone, subdomains, health, portfolio (desktop light), lookup and health (phone dark),
  reports (desktop dark) and scan (phone light);
- `shell-*`:
  - `kept-note`, `palette`, `workspaces`, `settings`, `shortcuts`;
  - `laptop-1366x768`, `tablet-860`;
  - `phone-header-target`, `phone-toolsmenu-{light,dark}`, `phone320-health`.

---

## Appendix C — decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| C1 | The certificate warn threshold: 21 days (Monitoring, the runner) or 30 days (Estate, CT radar default). | 30 for the UI. The runner keeps `--warn-days`, and Monitoring's warn band follows the runner's setting when it is in the results. |
| C2 | Global DNS under *Change & migrate DNS* (this spec) or next to DNS Lookup. | as specified; revisit after a week of use, since only `group` changes. |
| C3 | Extend **Report** to SSL Targets, Renewal readiness, Retire an IP and Domain portfolio. | yes, after phase 6, one tool at a time (lib/report.js kinds). |
| C4 | Self-host a licensed font (e.g. Inter, OFL, subset Latin + Latin Extended ≈ 45 KB woff2). | no. System fonts keep zero bytes and a native look; revisit only if Linux rendering proves a problem in the phase screenshots. |
| C5 | An optional workspace colour (an additive `color` in the workspace meta), shown in the switcher and on Home, so that work does not land in the wrong customer's workspace. | worth it; additive and small; phase 6 or later. |
| C6 | Domain portfolio does not save its list. Its box prefills from the 20 most recent domains, so an MSP with 50 domains per customer pastes them again, and Home covers only domains checked at least once (they stay in `rdapSeen`). | worth it, as an additive `watchlist` part: Portfolio prefills from it, and Home counts against it ("12 of 50 domains checked in the last 7 days"). It is a product change, outside this redesign. |
| C7 | An attention count per workspace in the switcher, so an MSP sees which customer needs a look without opening each workspace in turn. | later. The switcher would read every workspace's `rdapSeen`, `ctSeen` and `waivers` when it opens. It would show counts only, never domain names, since the switcher is on screen during screen-shares. |

---

## Review notes

This is a review of the first draft, made on 2026-10-09 against the code at d0163ee9 and the
audit's screenshots. Its numbers are measured: start-route sizes with the test's own graph walk,
contrast with the WCAG 2 formula, phone widths from `before/shell-phone320-health-light-en.png`,
and selector use with grep over `tests/e2e`.

**What changed:**

1. **Home's counts were not all true** (§4.1–4.2).
   - CT expiry counted the baseline's `ids`. Those keep a replaced certificate until it expires, so
     Home now reads a `due` list of the current certificates.
   - The rollout board never stored its total, so it gains an additive `total`.
   - The Monitoring digest lived in the page session, which a reload empties. It is now a small
     workspace part.
   - The lock rule disagreed with the Portfolio's, so Home now imports `statusRisk`.
   - Old snapshots read "as of <date>" (new principle 7).
   - The digest loads after first paint, off the start route.
2. **The phone bar did not fit** at 320 px or at 375 px: it needed ≈ 390 px. It is now
   `logo · Tools · TR|EN · ⚙`, and the Tools sheet hosts the palette's box. The selectors that
   ≈ 48 phone-width language switches and five helpers click stay where they are.
3. **Template** (§5).
   - The metric strip and the findings sit in the tab panel they count.
   - The metric strip is read-only, so a result filters in two places, not three.
   - One primary button is visible at a time, so Verify, Live check and CT keep their own run.
   - The input folds when a run starts, and the SSL Targets wizard folds too.
4. **Tokens** (§6).
   - No renames: 24 existing uses would have unset silently.
   - `--accent-solid-hover` is new: the dark hover was 4.15:1.
   - `--border-control` is new: controls reach ≥ 3:1 (K4).
   - `--surface-selected` is now neutral (K2).
   - The touch block now beats compact density.
   - New rules: no text on solid fills, forced colours, and no state carried by weight 500.
5. **IA** (§3).
   - The last group is *Setup & help*.
   - Home gets a label-less `NAV_GROUPS` entry, so it never falls into *More tools*.
   - The Settings dialog is described as it is: it has no theme or language.
6. **Rollout** (§8).
   - Phase 1 ships as 1a, 1b and 1c.
   - The 11 result-template components wait for phase 2, in a lazy ui/template.js.
   - The budget is recomputed: ≈ 350–355 KB during 1a–1b, ≈ 260–270 KB after 1c.
7. **TR/EN.** Five TR purpose lines exceeded the spec's own 80 characters. The straight
   apostrophes became ’, "Sıkı" became "Sıkışık", and the keys for the new rows are added.

**Kept as drafted:** the audit (plus K4), the job-based groups, the region model, the order of the
standard actions, the expiry bands, phases 2–6, and decisions C1–C5.

**Still open:** decisions C6 and C7 (new). In 1b, re-measure the phone bar and the 1366×657 sidebar
check with Linux fonts before the layout is frozen.
