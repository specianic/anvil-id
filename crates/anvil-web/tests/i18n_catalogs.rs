//! Catalog completeness (UI-04): every locale under `themes/default/locales/` defines exactly the
//! message ids of English, file by file, with no variables English does not declare, and keeps
//! English's plural selectors. A missing translation renders English at runtime; this test turns
//! it into a CI failure instead.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anvil_web::i18n::{Catalogs, FALLBACK, Locale};
use fluent_bundle::{FluentResource, FluentValue};

/// One message as written in a catalog file.
#[derive(Debug, Default)]
struct Message {
    /// `$name` references in the value and attributes.
    variables: BTreeSet<String>,
    /// Whether the message uses a select expression (`{ $n -> ... }`).
    selects: bool,
}

/// file name -> message id -> message.
type Files = BTreeMap<String, BTreeMap<String, Message>>;

fn locales_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default/locales")
}

/// `$name` references in one line.
fn variables(line: &str, into: &mut BTreeSet<String>) {
    let mut rest = line;
    while let Some(i) = rest.find('$') {
        let tail = &rest[i + 1..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(tail.len());
        if end > 0 {
            into.insert(tail[..end].to_owned());
        }
        rest = &tail[end..];
    }
}

/// The messages of one `.ftl` file. The file must parse as Fluent; messages are the entries that
/// start in column 0 (`id = ...`) and their indented continuation lines. The scan is cross-checked
/// against the Fluent parser's own message count.
fn messages(path: &Path) -> BTreeMap<String, Message> {
    let source = std::fs::read_to_string(path).expect("read catalog");
    let resource = match FluentResource::try_new(source.clone()) {
        Ok(r) => r,
        Err((_, errors)) => panic!("{} does not parse: {errors:?}", path.display()),
    };
    let parsed = resource
        .entries()
        .filter(|e| format!("{e:?}").starts_with("Message("))
        .count();

    let mut out: BTreeMap<String, Message> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in source.lines() {
        let indented = line.starts_with([' ', '\t']);
        if line.trim().is_empty() || (!indented && line.starts_with('#')) {
            if !indented && line.starts_with('#') {
                current = None;
            }
            continue;
        }
        if !indented {
            let (id, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{}: unexpected line {line:?}", path.display()));
            let id = id.trim().to_owned();
            assert!(
                !id.starts_with('-'),
                "{}: terms are not used by AnvilID catalogs ({id})",
                path.display()
            );
            assert!(
                !out.contains_key(&id),
                "{}: {id} defined twice",
                path.display()
            );
            let mut m = Message::default();
            variables(value, &mut m.variables);
            m.selects = value.contains("->");
            out.insert(id.clone(), m);
            current = Some(id);
        } else if let Some(id) = &current {
            let m = out.get_mut(id).expect("current message");
            variables(line, &mut m.variables);
            m.selects |= line.contains("->");
        }
    }
    assert_eq!(
        out.len(),
        parsed,
        "{}: the line scan and the Fluent parser disagree on the number of messages",
        path.display()
    );
    out
}

/// Every locale directory with its `.ftl` files.
fn load_all() -> BTreeMap<String, Files> {
    let mut all = BTreeMap::new();
    for dir in std::fs::read_dir(locales_root()).expect("locales dir") {
        let dir = dir.expect("entry").path();
        if !dir.is_dir() {
            continue;
        }
        let tag = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 name")
            .to_owned();
        let mut files = Files::new();
        for f in std::fs::read_dir(&dir).expect("locale dir") {
            let f = f.expect("entry").path();
            if f.extension().and_then(|e| e.to_str()) == Some("ftl") {
                let name = f
                    .file_name()
                    .and_then(|n| n.to_str())
                    .expect("utf-8 name")
                    .to_owned();
                files.insert(name, messages(&f));
            }
        }
        all.insert(tag, files);
    }
    all
}

/// The problems of `locale` measured against English, one line each.
fn compare(tag: &str, en: &Files, other: &Files) -> Vec<String> {
    let mut problems = Vec::new();
    for name in other.keys().filter(|n| !en.contains_key(*n)) {
        problems.push(format!("{tag}/{name}: no such file in en"));
    }
    for (name, en_msgs) in en {
        let Some(msgs) = other.get(name) else {
            problems.push(format!("{tag}/{name}: file missing"));
            continue;
        };
        for id in en_msgs.keys().filter(|id| !msgs.contains_key(*id)) {
            problems.push(format!("{tag}/{name}: missing {id}"));
        }
        for (id, m) in msgs {
            let Some(en_m) = en_msgs.get(id) else {
                problems.push(format!("{tag}/{name}: {id} is not an English message"));
                continue;
            };
            for v in m.variables.difference(&en_m.variables) {
                problems.push(format!(
                    "{tag}/{name}: {id} uses ${v}, which English does not declare"
                ));
            }
            if en_m.selects && !m.selects {
                problems.push(format!(
                    "{tag}/{name}: {id} must keep the plural selector of English"
                ));
            }
        }
    }
    problems
}

#[test]
fn every_locale_matches_english_file_by_file() {
    let all = load_all();
    let en = all.get(FALLBACK).expect("English catalogs");
    assert!(!en.is_empty(), "English has catalog files");
    assert!(all.contains_key("de"), "German is shipped");
    let problems: Vec<String> = all
        .iter()
        .filter(|(tag, _)| tag.as_str() != FALLBACK)
        .flat_map(|(tag, files)| compare(tag, en, files))
        .collect();
    assert!(
        problems.is_empty(),
        "catalogs differ from English:\n{}",
        problems.join("\n")
    );
}

#[test]
fn the_comparison_rejects_missing_extra_and_unknown_variables() {
    let msg = |vars: &[&str], selects: bool| Message {
        variables: vars.iter().map(|v| (*v).to_owned()).collect(),
        selects,
    };
    let mut en = Files::new();
    en.insert(
        "f.ftl".into(),
        BTreeMap::from([
            ("a".to_owned(), msg(&[], false)),
            ("b".to_owned(), msg(&["n"], true)),
        ]),
    );
    let mut xx = Files::new();
    xx.insert(
        "f.ftl".into(),
        BTreeMap::from([
            ("b".to_owned(), msg(&["n", "x"], false)),
            ("c".to_owned(), msg(&[], false)),
        ]),
    );
    xx.insert("g.ftl".into(), BTreeMap::new());
    let problems = compare("xx", &en, &xx).join("\n");
    assert!(
        problems.contains("xx/g.ftl: no such file in en"),
        "{problems}"
    );
    assert!(problems.contains("missing a"), "{problems}");
    assert!(
        problems.contains("c is not an English message"),
        "{problems}"
    );
    assert!(problems.contains("uses $x"), "{problems}");
    assert!(problems.contains("plural selector"), "{problems}");

    let mut no_file = Files::new();
    no_file.insert("g.ftl".into(), BTreeMap::new());
    assert!(
        compare("xx", &en, &no_file)
            .iter()
            .any(|p| p == "xx/f.ftl: file missing")
    );
}

#[test]
fn variable_scan_reads_placeholders_and_selectors() {
    let mut v = BTreeSet::new();
    variables("Try again in { $seconds -> [one] { $seconds } x }", &mut v);
    variables("Remove { $label } and {$other_one}", &mut v);
    assert_eq!(
        v.into_iter().collect::<Vec<_>>(),
        vec!["label", "other_one", "seconds"]
    );
}

#[test]
fn embedded_catalogs_load_with_german() {
    let c = Catalogs::load(None).expect("catalogs load");
    let available = c.available();
    assert!(available.contains(&"en".to_owned()), "{available:?}");
    assert!(available.contains(&"de".to_owned()), "{available:?}");

    let de = Locale::new("de");
    assert_eq!(c.text(&de, "title.login", &[]), "Anmelden");
    assert_eq!(
        c.text(
            &de,
            "login.too_many_attempts",
            &[("seconds", FluentValue::from(1))]
        ),
        "Zu viele Versuche. Versuchen Sie es in 1 Sekunde erneut."
    );
    assert_eq!(
        c.text(
            &de,
            "login.too_many_attempts",
            &[("seconds", FluentValue::from(30))]
        ),
        "Zu viele Versuche. Versuchen Sie es in 30 Sekunden erneut."
    );
    assert_eq!(
        c.text(
            &de,
            "upstream.continue_with",
            &[("provider", FluentValue::from("GitHub"))]
        ),
        "Weiter mit GitHub"
    );
}
