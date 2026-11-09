// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Images and files on the command line, as the Go cbb's (cmd/cbb,
//! internal/mediafile): cbb copy FILE... sends files and folders, or with
//! -type one image or HTML, cbb paste -o DIR saves what the clipboard
//! holds, and cbb paste -on pastes on another device. The files are read
//! and written as the user who runs cbb; their bytes go over the control
//! socket, and the service keeps them in its cache.

use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use cbb_core::media::{MAX_MEDIA, MAX_PARTS, MAX_PATH, MAX_PATHS, check_path, clean_name, save_path};

use crate::cli::usage;
use crate::control::{self, Header, Message, Part, Reader};
use crate::copies::size_text;
use crate::error::{Context, Error, Result};
use crate::{Global, check, flag, open, request};

/// The most text cbb copy and cbb paste -on take, as Go's maxText.
const MAX_TEXT: usize = 1 << 20;

/// The most text a paste typed key by key takes, as Go's MaxTypeText.
const MAX_TYPE_TEXT: usize = 4 << 10;

/// How many bytes of a file go in one data message.
const CHUNK: usize = 1 << 20;

/// The clipboard data type that -type names: png, jpeg, gif or html, or
/// the type itself, as Go's mediaType.
fn media_type(t: &str) -> Result<&'static str> {
    Ok(match t.to_lowercase().as_str() {
        "png" | "image/png" => "image/png",
        "jpeg" | "jpg" | "image/jpeg" => "image/jpeg",
        "gif" | "image/gif" => "image/gif",
        "html" | "text/html" => "text/html",
        _ => return Err(usage(format!("-type is png, jpeg, gif or html, not {t:?}"))),
    })
}

/// A part to send, with the file it comes from; None for a folder.
type Sent = (Part, Option<PathBuf>);

/// A file's name as a manifest holds it, as Go's clip.CleanName: the bytes
/// that are no UTF-8 become "_".
fn os_name(name: &std::ffi::OsStr) -> String {
    #[cfg(unix)]
    let text = {
        use std::os::unix::ffi::OsStrExt;
        let mut s = String::new();
        for chunk in name.as_bytes().utf8_chunks() {
            s.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                s.push('_');
            }
        }
        s
    };
    #[cfg(not(unix))]
    let text = name.to_string_lossy().into_owned();
    clean_name(&text)
}

/// The parts of a copy as they are collected, with the checks of Go's
/// mediafile.Collect.
#[derive(Default)]
struct Collector {
    parts: Vec<Sent>,
    seen: std::collections::HashSet<String>,
    names: usize,
    skipped: usize,
}

impl Collector {
    fn add(&mut self, p: Part, file: Option<PathBuf>) -> Result<()> {
        if !self.seen.insert(p.path.clone()) {
            return Err(Error::msg(format!("two files would be {:?} in the copy", p.path)));
        }
        self.names += p.path.len();
        if self.parts.len() == MAX_PARTS {
            return Err(Error::msg(format!("a copy has at most {MAX_PARTS} files and folders")));
        }
        if self.names > MAX_PATHS {
            return Err(Error::msg("the names in the copy are too long together"));
        }
        if p.path.len() > MAX_PATH {
            return Err(Error::msg(format!("the path {:?} is too long", p.path)));
        }
        self.parts.push((p, file));
        Ok(())
    }

    /// Adds the tree under the folder dir, named name in the copy, in the
    /// order of its names, as Go's filepath.WalkDir does.
    fn walk(&mut self, dir: &Path, name: &str) -> Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .context(format!("cannot read {}", dir.display()))?
            .collect::<std::io::Result<_>>()
            .context(format!("cannot read {}", dir.display()))?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let t = e.file_type().context(format!("cannot read {}", e.path().display()))?;
            let child = format!("{name}/{}", os_name(&e.file_name()));
            if t.is_dir() {
                self.add(Part { path: child.clone(), dir: true, ..Default::default() }, None)?;
                self.walk(&e.path(), &child)?;
            } else if t.is_file() {
                let size = e.metadata().context(format!("cannot read {}", e.path().display()))?.len();
                self.add(Part { path: child, size: size as i64, ..Default::default() }, Some(e.path()))?;
            } else {
                // Links are neither followed nor sent.
                self.skipped += 1;
            }
        }
        Ok(())
    }
}

/// The parts of a copy of the files and folders at paths, as Go's
/// mediafile.Collect: each by its cleaned name, a folder with its tree,
/// links and special files left out (it returns how many).
fn collect(paths: &[String]) -> Result<(Vec<Sent>, usize)> {
    let mut c = Collector::default();
    for arg in paths {
        let abs = std::path::absolute(arg).context(format!("cannot find {arg}"))?;
        let info = std::fs::metadata(&abs).context(format!("cannot read {arg}"))?;
        let top = abs.file_name().map_or_else(|| "_".to_string(), os_name);
        if !info.is_dir() {
            if !info.is_file() {
                return Err(Error::msg(format!("{arg} is not a file or a folder")));
            }
            c.add(Part { path: top, size: info.len() as i64, ..Default::default() }, Some(abs))?;
            continue;
        }
        c.add(Part { path: top.clone(), dir: true, ..Default::default() }, None)?;
        c.walk(&abs, &top)?;
    }
    Ok((c.parts, c.skipped))
}

/// cbb copy FILE...: sends the files at paths, or with typ the one file as
/// an image or HTML, with text as its plain text, as Go's copyMedia.
pub(crate) fn copy(g: &Global, paths: &[String], typ: &str, text: &str) -> Result<()> {
    let parts = if !typ.is_empty() {
        let [path] = paths else { return Err(usage("copy -type takes one file")) };
        let t = media_type(typ)?;
        let info = std::fs::metadata(path).context(format!("cannot read {path}"))?;
        if !info.is_file() {
            return Err(Error::msg(format!("{path} is not a file")));
        }
        vec![(Part { kind: t.into(), size: info.len() as i64, ..Default::default() }, Some(PathBuf::from(path)))]
    } else {
        let (parts, skipped) = collect(paths)?;
        if skipped > 0 {
            eprintln!("cbb: left out {skipped} links and special files; only files and folders are copied");
        }
        parts
    };
    let total: i64 = parts.iter().map(|(p, _)| p.size).sum();
    if total > MAX_MEDIA {
        return Err(Error::msg(format!("the copy is {}; CBB carries at most 1 GiB", size_text(total))));
    }
    let mut h = Header { op: "copy-media".into(), ..Default::default() };
    let conn = open(g, &mut h)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    let mut r = Reader::new(conn);
    if let Err(e) = send(&mut w, h, &parts, text) {
        // The service may have refused the copy midway and said why.
        if let Ok(Some(m)) = r.read() {
            check(m)?;
        }
        return Err(e);
    }
    check(r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))?)?;
    println!("Copied {} to the group.", describe(&parts, total));
    Ok(())
}

/// Sends the request h with text as the copy's plain-text alternative,
/// each part and its bytes, and the end, as Go's mediafile.Send.
fn send(w: &mut impl Write, h: Header, parts: &[Sent], text: &str) -> Result<()> {
    control::write(w, &Message::new(h, text.as_bytes().to_vec()))?;
    let mut buf = vec![0; CHUNK];
    for (p, file) in parts {
        control::write(
            w,
            &Message::new(Header { op: "part".into(), part: Some(p.clone()), ..Default::default() }, Vec::new()),
        )?;
        let Some(file) = file.as_ref().filter(|_| !p.dir) else { continue };
        let mut f = File::open(file).context(format!("cannot read {}", file.display()))?;
        let mut left = p.size as usize;
        while left > 0 {
            let want = left.min(buf.len());
            let n = read_full(&mut f, &mut buf[..want]).context(format!("cannot read {}", file.display()))?;
            if n > 0 {
                control::write(
                    w,
                    &Message::new(Header { op: "data".into(), ..Default::default() }, buf[..n].to_vec()),
                )?;
                left -= n;
            }
            if n < want {
                return Err(Error::msg(format!("{} changed while it was copied", file.display())));
            }
        }
    }
    control::write(w, &Message::new(Header { op: "part".into(), done: true, ..Default::default() }, Vec::new()))
}

/// Reads until buf is full or the file ends, as Go's io.ReadFull.
fn read_full(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            m => n += m,
        }
    }
    Ok(n)
}

/// What a copy holds: an image, a file, or so many files and folders, and
/// its size, as Go's describe.
fn describe(parts: &[Sent], total: i64) -> String {
    let (mut files, mut dirs) = (0, 0);
    for (p, _) in parts {
        if !p.kind.is_empty() {
            return format!("the {} ({})", p.kind, size_text(total));
        }
        if p.dir {
            dirs += 1;
        } else {
            files += 1;
        }
    }
    match (dirs, files) {
        (0, 1) => format!("{} ({})", parts[0].0.path, size_text(total)),
        (0, _) => format!("{files} files ({})", size_text(total)),
        _ => format!("{files} files in {dirs} folders ({})", size_text(total)),
    }
}

/// cbb paste -o DIR: saves the clipboard's images or files in dir, as Go's
/// pasteMedia and mediafile.Save.
pub(crate) fn paste_to(g: &Global, dir: &str) -> Result<()> {
    if !Path::new(dir).is_dir() {
        return Err(Error::msg(format!("{dir} is not a folder")));
    }
    let mut h = Header { op: "paste-media".into(), ..Default::default() };
    let conn = open(g, &mut h)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(&mut w, &Message::new(h, Vec::new()))?;
    let mut r = Reader::new(conn);
    check(next(&mut r)?)?;
    let mut made: Vec<PathBuf> = Vec::new();
    match save(&mut r, Path::new(dir), &mut made) {
        Ok(top) => {
            for t in top {
                println!("{}", t.display());
            }
            Ok(())
        }
        Err(e) => {
            for p in made.iter().rev() {
                let _ = std::fs::remove_file(p).or_else(|_| std::fs::remove_dir(p));
            }
            Err(e)
        }
    }
}

/// The service's next message on r.
fn next(r: &mut Reader<crate::sys::UnixStream>) -> Result<Message> {
    let m = r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    check(m)
}

/// Writes the parts the service sends into dir until its last answer: files
/// and folders by their names, an image as image.png, image.jpg or
/// image.gif, HTML as clipboard.html. It never replaces a file and makes
/// nothing executable; made lists what it made, for the caller to remove
/// on a failure. It returns the copy's top names.
fn save(r: &mut Reader<crate::sys::UnixStream>, dir: &Path, made: &mut Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let mut top = Vec::new();
    loop {
        let m = next(r)?;
        if m.header.done {
            return Ok(top);
        }
        let p = m.header.part.ok_or_else(|| Error::msg("the service sent bytes without their part"))?;
        let name = saved_name(&p)?;
        let target = name.split('/').fold(dir.to_path_buf(), |t, n| t.join(n));
        if !name.contains('/') {
            top.push(target.clone());
        }
        if p.dir {
            std::fs::create_dir(&target).context(format!("cannot make {}", target.display()))?;
            made.push(target);
            continue;
        }
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o644);
        let mut f = o.open(&target).context(format!("cannot write {}", target.display()))?;
        made.push(target.clone());
        let mut got = 0i64;
        while got < p.size {
            let d = next(r)?;
            let n = d.payload.len() as i64;
            if d.header.part.is_some() || d.header.done || n == 0 || n > p.size - got {
                return Err(Error::msg("the service sent the bytes of a part not as said"));
            }
            f.write_all(&d.payload).context(format!("cannot write {}", target.display()))?;
            got += n;
        }
        f.sync_all().context(format!("cannot write {}", target.display()))?;
    }
}

/// Where a part goes in the folder: its path, checked again, with the
/// device names of Windows renamed, or a name for its type, as Go's
/// mediafile.SavedName.
fn saved_name(p: &Part) -> Result<String> {
    Ok(match p.kind.as_str() {
        "" => {
            check_path(&p.path).map_err(|e| Error::msg(e.message()))?;
            save_path(&p.path)
        }
        "image/png" => "image.png".into(),
        "image/jpeg" => "image.jpg".into(),
        "image/gif" => "image.gif".into(),
        "text/html" => "clipboard.html".into(),
        t => return Err(Error::msg(format!("the clipboard holds {t}, which this cbb does not know"))),
    })
}

/// cbb paste -on DEVICE: pastes standard input, or this clipboard when
/// standard input is a terminal, where the focus is on another device; with
/// files, or -copy, images or files instead, as Go's cmdPasteOn.
pub(crate) fn paste_on(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb paste -on DEVICE [-type] [-enter] [-secret] < text\n       cbb paste -on DEVICE [-enter] [-image] FILE...\n       cbb paste -on DEVICE [-enter] -copy";
    let (mut on, mut typed, mut enter, mut secret, mut image, mut current) =
        (String::new(), false, false, false, false, false);
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("on") => on = it.next().cloned().ok_or_else(|| usage(USE))?,
            Some("type") => typed = true,
            Some("enter") => enter = true,
            Some("secret") => secret = true,
            Some("image") => image = true,
            Some("copy") => current = true,
            Some(_) => return Err(usage(USE)),
            None => {
                files.push(a.clone());
                files.extend(it.by_ref().cloned());
            }
        }
    }
    let media = !files.is_empty() || current || image;
    if on.is_empty() || media && (typed || secret) || current && !files.is_empty() || image && files.len() != 1 {
        return Err(usage(USE));
    }
    let mut h = Header {
        op: "paste-on".into(),
        device: on.clone(),
        method: "paste".into(),
        enter,
        kind: "text".into(),
        ..Default::default()
    };
    if media {
        if !files.is_empty() {
            let mut typ = "";
            if image {
                let ext =
                    Path::new(&files[0]).extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
                typ = match ext.as_str() {
                    "png" => "png",
                    "jpg" | "jpeg" => "jpeg",
                    _ => return Err(Error::msg(format!("-image takes a .png or .jpg file, not {}", files[0]))),
                };
            }
            copy(g, &files, typ, "")?;
        }
        h.kind = "media".into();
        request(g, &Message::new(h, Vec::new()))?;
        println!("Pasted on {on}.");
        return Ok(());
    }
    if typed {
        h.method = "type".into();
    }
    if secret {
        h.kind = "secret".into();
    }
    let text = if std::io::stdin().is_terminal() {
        let m = request(g, &Message::new(Header { op: "paste".into(), ..Default::default() }, Vec::new()))?;
        if m.header.kind == "secret" {
            h.kind = "secret".into();
        }
        m.payload
    } else {
        let mut text = Vec::new();
        std::io::stdin().take(MAX_TEXT as u64 + 1).read_to_end(&mut text).context("cannot read standard input")?;
        if text.len() > MAX_TEXT {
            return Err(Error::msg("the text is larger than 1 MiB"));
        }
        text
    };
    if typed && text.len() > MAX_TYPE_TEXT {
        return Err(Error::msg(format!(
            "the text is longer than {MAX_TYPE_TEXT} bytes, too long to type; paste it without -type"
        )));
    }
    request(g, &Message::new(h, text))?;
    println!("Pasted on {on}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_a_tree() {
        let dir = std::env::temp_dir().join(format!("cbb-collect-{}", crate::files::random_name()));
        std::fs::create_dir_all(dir.join("top/sub")).unwrap();
        std::fs::write(dir.join("top/b.txt"), b"bb").unwrap();
        std::fs::write(dir.join("top/sub/a:b.txt"), b"a").unwrap();
        std::fs::write(dir.join("one.pdf"), b"pdf").unwrap();
        let args = [dir.join("top").display().to_string(), dir.join("one.pdf").display().to_string()];
        let (parts, skipped) = collect(&args).unwrap();
        let got: Vec<(String, bool, i64)> = parts.iter().map(|(p, _)| (p.path.clone(), p.dir, p.size)).collect();
        assert_eq!(
            got,
            [
                ("top".to_string(), true, 0),
                ("top/b.txt".to_string(), false, 2),
                ("top/sub".to_string(), true, 0),
                ("top/sub/a_b.txt".to_string(), false, 1),
                ("one.pdf".to_string(), false, 3),
            ]
        );
        assert_eq!(skipped, 0);
        assert_eq!(describe(&parts, 6), "3 files in 2 folders (6 bytes)");
        assert!(collect(&[args[1].clone(), args[1].clone()]).is_err(), "the same name twice");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn types_and_names() {
        assert_eq!(media_type("JPG").unwrap(), "image/jpeg");
        assert!(media_type("bmp").is_err());
        let p = |kind: &str, path: &str| Part { kind: kind.into(), path: path.into(), ..Default::default() };
        assert_eq!(saved_name(&p("image/png", "")).unwrap(), "image.png");
        assert_eq!(saved_name(&p("", "com0.txt")).unwrap(), "com0_.txt");
        assert!(saved_name(&p("", "CON.txt")).is_err());
        assert!(saved_name(&p("", "../x")).is_err());
        assert!(saved_name(&p("image/bmp", "")).is_err());
    }
}
