// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The C side of the macOS pasteboard binding. A NULL or empty name is the
// general pasteboard; another name is a private pasteboard, for tests.

#define CB_SECRET 1 // a password manager marked the item
#define CB_REMOTE 2 // the item came through Universal Clipboard

#define CB_PNG 0 // the types of an image
#define CB_JPEG 1
#define CB_GIF 2

long cb_change_count(const char *name);
int cb_read(const char *name, char **text, long *len, int *flags, long *change);
long cb_write(const char *name, const char *text, long len, int secret);
int cb_read_image(const char *name, void **data, long *len, int *type, long *change, long max);
long cb_write_image(const char *name, const void *data, long len, int type, const char *text, long textlen);
int cb_read_html(const char *name, char **html, long *len, long max);
long cb_write_html(const char *name, const char *html, long len, const char *text, long textlen);
int cb_read_files(const char *name, char **paths, long *len, long *change);
long cb_write_files(const char *name, const char *paths, long len);
long cb_clear(const char *name);
void cb_release(const char *name);
