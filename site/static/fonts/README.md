<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Fonts

The site's typefaces, the same as the apps': IBM Plex Sans for the text, IBM Plex Mono for
labels and codes, and IBM Plex Sans Arabic, Hebrew and Devanagari for those scripts. They are
served from cbb.tools itself so that pages load nothing from other sites: the WOFF2 files
Google Fonts serves, unchanged. IBM Plex Sans is one variable file per subset (Latin, Latin
Extended, Cyrillic), with every weight from 400 to 600 in it. Chinese uses the system's font
(Noto Sans SC where it is installed). Each family is under the SIL Open Font License 1.1, in
the `OFL-*.txt` file of its name:

| Family | Source | License |
| --- | --- | --- |
| IBM Plex Sans | <https://fonts.google.com/specimen/IBM+Plex+Sans> | `OFL-ibmplexsans.txt` |
| IBM Plex Mono | <https://fonts.google.com/specimen/IBM+Plex+Mono> | `OFL-ibmplexmono.txt` |
| IBM Plex Sans Arabic | <https://fonts.google.com/specimen/IBM+Plex+Sans+Arabic> | `OFL-ibmplexsansarabic.txt` |
| IBM Plex Sans Hebrew | <https://fonts.google.com/specimen/IBM+Plex+Sans+Hebrew> | `OFL-ibmplexsanshebrew.txt` |
| IBM Plex Sans Devanagari | <https://fonts.google.com/specimen/IBM+Plex+Sans+Devanagari> | `OFL-ibmplexsansdevanagari.txt` |
