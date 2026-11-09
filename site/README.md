<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The website

The project's website at <https://cbb.tools>: three pages (the start page, download, and
security and privacy) in English and every language of `l10n/` (Chinese, Hindi, Spanish, Russian, Arabic, Swahili, Hebrew), and the
documentation at `/docs/` (the index and the users' guides in every language, the rest in English), built by
[`tools/site`](../tools/site/main.go) into plain HTML and CSS. It loads nothing from other
sites. Its scripts are all served by the same server: its own `static/theme.js`, a few lines
that put the reader's light or dark theme on the page before it is drawn, and
`static/site.js`, deferred, which runs the theme button, the copy buttons and the drawings' motion and,
on the download page, puts the reader's system first; and the visit counter, GoatCounter (the other `<script>` elements are schema.org data
for search engines). Without scripts every page works: the theme follows the system and
every way to download is shown. It also has error pages (`404`, `50x`) in every language, which nginx shows.

## Editing

- The pages are `templates/*.html` inside `templates/layout.html`, written in English. Every
  text a reader sees goes through `t`: `{{t "Download"}}`, or with a link or a command in it
  `{{t "Run %s on the computer." (code "sudo cbb pair")}}`.
- Each other language is `l10n/<language>.json`: every English text and its translation, and
  `@name` (the language's own name), `@lang` (its `lang` tag, when not its code) and `@dir`
  (`rtl` for Arabic and Hebrew). A new language is a new file.
- `go run ./tools/site check` fails when a language lacks a text, keeps one no page uses, or a
  translation has another number of `%s`; CI runs it. After changing an English text, change
  its key in every language, and mark the translation for review in the pull request.
- The questions of the start page are `faq` in `tools/site/build.go`, also given to search
  engines as a FAQPage; their answers are plain text, with no links.
- Write for the reader: the benefit first, short sentences, buttons that say what happens
  ("Download for Android", not "More"), and a next step at the end of every page. State only
  what is true today: no invented reviews or numbers, and what is planned says so.
- The design is the blueprint, the same as the apps': a white sheet with blue lines in the
  light theme, a blueprint in the dark one, both on a fine grid; IBM Plex Sans for the text and
  IBM Plex Mono for labels and codes (`static/fonts`). Its colours are tokens at the top of
  `static/style.css`, the light theme's in a block of its own, taken from the apps' design
  tokens. A solid line means on or working, a dashed one off or waiting, and corner marks show
  the active element; radii are 3 px. Each section is a numbered sheet and each picture a
  numbered figure, with the words "Sheet" and "Fig." translated. The theme follows the system
  until the reader picks one with the button in the header. Motion is CSS only, 0.2 to 0.6 s
  (a drawing's lines are drawn in about a second), and off under `prefers-reduced-motion`.
  Buttons are at least 44 px high.
- The pictures are line drawings with numbered callouts, explained in a list under them. The
  lines are drawn once by rough.js with no roughness: change `chalk.js` and run
  `npm run chalk`, which writes `templates/chalk.html`; the labels stay in the pages, in each
  language.
- `static/og/<language>.jpg` (1200×630) is the picture links to the site show in chats and
  social networks: the home page's title beside its figure 1. After changing either, run
  `npm run og` (Playwright's Chromium, and Noto fonts for Chinese, Arabic, Hebrew and Hindi;
  see `og.js`).
- Name every phone and computer the same way: "a phone or a computer", "iPhone, Android,
  Mac, Windows or Linux". Name the iPhone alone only where only the iPhone is meant.
- A comparison with other apps states only what their makers' own pages say, with the
  date, and marks what is partly true as such.
- Present both kinds of group as nearly equal: with a computer at its heart (simpler, and
  said so) and phones only (fully supported).

## The documentation

`/docs/` is the repository's documentation as it reads on GitHub: every Markdown page below
`docs/`, and the few pages elsewhere that it links to (`extraDocs` in
[`tools/site/docs.go`](../tools/site/docs.go): CONTRIBUTING, SECURITY, the changelog, the
lite member's and the Docker image's READMEs), rendered with goldmark inside
`templates/doc.html`. Nothing is written for the site alone: change a page in `docs/` and
the next build carries it. A link to another published page leads to its page here, a link
to any other file of the repository to that file on GitHub, and `docs/images` is copied.
The headings keep GitHub's anchors, so the links `tools/repocheck` checks work on both;
anchors may begin with a digit, which `.htmlvalidate.json` allows. Each page links to its
source on GitHub. The documentation's pages are in the sitemap, and Lighthouse measures its
index and its longest page, the protocol.

### Translations

The index and the pages of `docs/guide` open inside the site in every language. A page is
`site/docs/<language>/guide/<page>.md`: the English page with its text translated and
everything else unchanged (the same headings in the same order, the same links, pictures and
code blocks; link texts and picture descriptions may be translated). The headings keep the
English anchors in every language. `go run ./tools/site check` reports a translation that
differs in shape, and `-strict` also one that follows an older page; after bringing a
translation up to date, `go run ./tools/site docs-sync` renews its `source` line. A page not
translated yet shows in English with a note. The index is read line by line through
`l10n/<language>.json`. Every other page of `docs/` is English only: the index links to it on
GitHub. The pictures are shared; the text inside them is translated in
`tools/diagrams/l10n/<language>.json` and written to `docs/images/<language>/`.

## Previewing

```sh
go run ./tools/site build                     # writes site/out
go run ./tools/site serve -preview            # http://127.0.0.1:8780
```

`serve` picks the language as on the server, from the browser's languages; with
`-geo dbip-country-lite-YYYY-MM.csv.gz` by country too.

## Checks

`go test ./tools/site` builds the site and checks every page: one `h1`, canonical links,
`noindex` only on the error pages, valid schema.org data, the sitemap, and that every link
within the site leads to a file the build wrote. CI's `website` job also validates the HTML
and runs Lighthouse three times on each of a few pages (`go run ./tools/site lighthouse`),
served gzipped as nginx serves them;
it fails when a page's median is below 0.9 for performance and SEO and 0.95 for
accessibility. To run it here (`CHROME_PATH` if Chrome is not found by itself):

```sh
go run ./tools/site build
cd site && npm ci --ignore-scripts && npm run validate && npm run lighthouse
```

The build also writes a gzipped copy of each text file for nginx's `gzip_static`, names the
stylesheet by a hash of its contents so browsers can keep it for good, takes the latest
version on the download page from `CHANGELOG.md`, and writes `.well-known/security.txt`
(RFC 9116, expiring a year after the latest release) and `site.webmanifest`.

## How the language is chosen

`/` is the one address that is not a file. nginx passes it to `tools/site serve`, which
redirects to `/<language>/` by, in order: the language the visitor picked in the menu (the
`lang` cookie, set only then); the visitor's country, looked up in DB-IP's free
"IP to Country Lite" database on the server, with the browser's languages deciding where a
country has several of the site's; the browser's languages; English. The address is used for
this one lookup: neither nginx nor the chooser logs it. The site credits DB-IP, as its
license (CC BY 4.0) asks.

## The server

On cbb.tools, beside the forwarder and the relay, which keep their own ports. The owner
installs and changes it; nothing here does it by itself.

1. nginx from nginx.org's repository, with its ACME module, which gets and renews the
   certificates from Let's Encrypt; Ubuntu's own packages do not carry the module yet:

   ```sh
   sudo apt install curl gnupg2 ca-certificates lsb-release ubuntu-keyring
   curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
   echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
   sudo apt update && sudo apt install nginx nginx-module-acme
   ```

   Add `load_module modules/ngx_http_acme_module.so;` at the top of
   `/etc/nginx/nginx.conf`, copy [`deploy/nginx.conf`](deploy/nginx.conf) to
   `/etc/nginx/conf.d/cbb.tools.conf`. Its `access_log off` cancels `nginx.conf`'s access
   log, since the site promises none.
2. DNS: `cbb.tools` already points at the server; add `www.cbb.tools` (a CNAME to
   `cbb.tools`), which redirects to `cbb.tools`.
3. The firewall: TCP 80 and 443. The site has no HTTP/3, so it needs no UDP port.
4. The language chooser: build it with `GOOS=linux GOARCH=amd64 go build -o cbb-site
   ./tools/site`, copy it to `/usr/local/bin/cbb-site`, copy
   [`deploy/cbb-site.service`](deploy/cbb-site.service),
   [`deploy/cbb-site-geo.service`](deploy/cbb-site-geo.service) and
   [`deploy/cbb-site-geo.timer`](deploy/cbb-site-geo.timer) to `/etc/systemd/system`, then
   `sudo systemctl daemon-reload`, `sudo systemctl start cbb-site-geo.service` (the first
   database), `sudo systemctl enable --now cbb-site.service cbb-site-geo.timer`. It
   starts only once `/srv/cbb.tools/www/en/index.html` is there (step 6), and looks at the
   languages in `/srv/cbb.tools/www` on every request, so a copy of the pages needs no
   restart.
5. The visit counter, [GoatCounter](https://github.com/arp242/goatcounter): download the
   `linux-amd64` binary of its latest release to `/usr/local/bin/goatcounter`, then

   ```sh
   sudo useradd --system --home-dir /var/lib/goatcounter --shell /usr/sbin/nologin goatcounter
   sudo install -d -o goatcounter -g goatcounter /var/lib/goatcounter
   sudo -u goatcounter goatcounter db create site -db sqlite+/var/lib/goatcounter/db.sqlite3 \
       -createdb -vhost stats.localhost -user.email YOU@EXAMPLE.COM   # asks for the password
   ```

   copy [`deploy/cbb-site-stats.service`](deploy/cbb-site-stats.service) to
   `/etc/systemd/system`, `sudo systemctl daemon-reload` and `sudo systemctl enable --now
   cbb-site-stats.service`. It listens only on `127.0.0.1:8781`, and its dashboard is not on
   the internet: open it through SSH with `ssh -L 8781:127.0.0.1:8781 SERVER` and
   <http://stats.localhost:8781> (GoatCounter wants a name of two labels, and browsers send
   every `*.localhost` name to this computer). The buttons that count presses carry
   `data-goatcounter-click`.
6. The pages: `go run ./tools/site build`, then copy `site/out/` to `/srv/cbb.tools/www/`;
   `sudo nginx -t && sudo systemctl reload nginx`.
7. Search engines: in [Google Search Console](https://search.google.com/search-console)
   add the domain property `cbb.tools` and prove it with the TXT record it gives, in the
   domain's DNS; then submit `https://cbb.tools/sitemap.xml`. [Bing Webmaster
   Tools](https://www.bing.com/webmasters) can import the site from Search Console. Neither
   puts anything on the pages.

Each change of the pages is step 6 again.

## VLESS

The project's forwarder takes VLESS over XHTTP behind this nginx (`CBB_FORWARD_FLAGS=-vless-xhttp
cbb.tools` in `/etc/cbb/forward.env`; [self-hosting](../docs/admin/self-hosting.md)). It prints
its path at start (`journalctl -u cbb-forward | grep XHTTP`); give it to nginx, outside the
repository:

```sh
P=/PATH-FROM-THE-LOG
echo "\"~^$P(/|\$)\" 1;" | sudo tee /etc/nginx/cbb-vless-path.conf
sudo tee /etc/nginx/cbb-vless-location.conf <<EOF
location $P {
    client_max_body_size 32k;
    limit_req zone=cbb_vless_addr burst=300 nodelay;
    limit_conn cbb_vless_conn 16;
    limit_conn cbb_vless_all 1024;
    limit_req_status 429;
    limit_conn_status 429;
    proxy_pass http://cbb_vless;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_redirect off;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
EOF
sudo nginx -t && sudo systemctl reload nginx
```

The limits keep what a stranger makes the forwarder hold small (docs/relay-budget.md,
"XHTTP"); `client_max_body_size` matches the forwarder's largest upload, 32 KiB. On a server
set up before them, add the five `limit_` lines, `client_max_body_size` and the `X-Real-IP` line
(the client's address, which the forwarder charges) to the location in
`/etc/nginx/cbb-vless-location.conf`, and the zones from `deploy/nginx.conf` to the site's
configuration.

The path stays open while the site is closed; the http block's `access_log off` keeps it out
of the log.

## Closed until launch

Until the project opens, every visitor sees `soon.html` ("the website opens soon", in every
language), and search engines are told not to index anything, while the owner sees the whole
site. Before reloading nginx, create `/etc/nginx/cbb-preview.conf` with a secret of your own:

```sh
SECRET=$(openssl rand -hex 16)
echo "map \$cookie_cbb_preview \$cbb_closed { default 1; \"$SECRET\" 0; }" | sudo tee /etc/nginx/cbb-preview.conf
echo "https://cbb.tools/preview?key=$SECRET"
```

Open that link once in each browser that should see the site: it sets a cookie for a year.
The key must be 16 to 128 letters, digits, `-` or `_` (the hex above is), and `/preview`
takes a few tries a minute from one address.
The secret stays on the server; anyone given the link sees the site too. `/attest/`, the
counter and `/static/` stay open. To launch, make the file
`map $cookie_cbb_preview $cbb_closed { default 0; }` and `sudo nginx -t && sudo systemctl
reload nginx`.
