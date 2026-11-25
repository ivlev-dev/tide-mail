use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use rayon::prelude::*;
use rust_stemmers::{Algorithm, Stemmer};
use serde::{Deserialize, Serialize};
use tide_core::Message;
use unicode_segmentation::UnicodeSegmentation;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 500;
const SUBJECT_WEIGHT: f64 = 2.5;
const BODY_WEIGHT: f64 = 1.0;
const FROM_WEIGHT: f64 = 1.5;

#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub account_id: Option<String>,
    pub mailbox: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub from: Option<String>,
    pub text: Option<String>,
    pub limit: usize,
    pub offset: usize,
    pub include_deleted: bool,
}

impl SearchQuery {
    pub fn new() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            ..Self::default()
        }
    }

    pub fn account(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = Some(account_id.into());
        self
    }

    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    pub fn subject(mut self, text: impl Into<String>) -> Self {
        self.subject = Some(text.into());
        self
    }

    pub fn body(mut self, text: impl Into<String>) -> Self {
        self.body = Some(text.into());
        self
    }

    pub fn from(mut self, text: impl Into<String>) -> Self {
        self.from = Some(text.into());
        self
    }

    pub fn mailbox(mut self, mailbox: impl Into<String>) -> Self {
        self.mailbox = Some(mailbox.into());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    pub fn include_deleted(mut self, include: bool) -> Self {
        self.include_deleted = include;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub id: String,
    pub account_id: String,
    pub mailbox: String,
    pub subject: String,
    pub from: String,
    pub date: i64,
    pub flags: u64,
    pub score: u64,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Doc {
    pub id: String,
    pub account_id: String,
    pub mailbox: String,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub from_addresses: Vec<tide_core::Address>,
    pub to_addresses: Vec<tide_core::Address>,
    pub cc_addresses: Vec<tide_core::Address>,
    pub thread_id: String,
    pub message_id_header: String,
    pub size: u64,
    pub date: i64,
    pub flags: u64,
    pub body: String,
}

impl From<&Message> for Doc {
    fn from(message: &Message) -> Self {
        Self {
            id: message.id.clone(),
            account_id: message.account_id.clone(),
            mailbox: message.mailbox.clone(),
            subject: message.subject.clone(),
            from: message
                .from
                .iter()
                .map(|address| {
                    if let Some(name) = &address.name {
                        format!("{name} <{}>", address.email)
                    } else {
                        address.email.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
            to: message
                .to
                .iter()
                .map(|address| {
                    if let Some(name) = &address.name {
                        format!("{name} <{}>", address.email)
                    } else {
                        address.email.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
            cc: message
                .cc
                .iter()
                .map(|address| {
                    if let Some(name) = &address.name {
                        format!("{name} <{}>", address.email)
                    } else {
                        address.email.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
            from_addresses: message.from.clone(),
            to_addresses: message.to.clone(),
            cc_addresses: message.cc.clone(),
            thread_id: message.thread_id.clone(),
            message_id_header: message.message_id.clone(),
            size: message.size,
            date: message.date,
            flags: message.flags,
            body: message.body_text.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Posting {
    doc: u32,
    tf: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Postings {
    shards: Vec<HashMap<String, Vec<Posting>>>,
}

impl Default for Postings {
    fn default() -> Self {
        Self {
            shards: (0..16).map(|_| HashMap::new()).collect(),
        }
    }
}

impl Postings {
    fn shard(term: &str) -> usize {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in term.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (hash as usize) % 16
    }

    fn get(&self, term: &str) -> Option<&Vec<Posting>> {
        self.shards[Self::shard(term)].get(term)
    }

    fn push(&mut self, term: &str, posting: Posting) {
        self.shards[Self::shard(term)]
            .entry(term.to_string())
            .or_default()
            .push(posting);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Slot {
    doc: Doc,
    deleted: bool,
    length: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchIndex {
    slots: Vec<Slot>,
    by_id: HashMap<String, u32>,
    subject_terms: Postings,
    body_terms: Postings,
    from_terms: Postings,
    to_terms: Postings,
    total_length: u64,
    active_docs: u64,
}

impl SearchIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn insert(&mut self, message: &Message) {
        self.insert_doc(Doc::from(message));
    }

    pub(crate) fn insert_doc(&mut self, doc: Doc) {
        if let Some(previous) = self.by_id.remove(&doc.id) {
            if let Some(slot) = self.slots.get_mut(previous as usize) {
                if !slot.deleted {
                    slot.deleted = true;
                    self.active_docs = self.active_docs.saturating_sub(1);
                    self.total_length = self.total_length.saturating_sub(u64::from(slot.length));
                }
            }
        }
        let doc_id = match u32::try_from(self.slots.len()) {
            Ok(value) => value,
            Err(_) => return,
        };
        let subject_tokens = tokenize(&doc.subject);
        let body_tokens = tokenize(&doc.body);
        let from_tokens = tokenize(&doc.from);
        let to_tokens = tokenize(&doc.to);
        let length = subject_tokens.len() + body_tokens.len();

        add_terms(&mut self.subject_terms, doc_id, &subject_tokens);
        add_terms(&mut self.body_terms, doc_id, &body_tokens);
        add_terms(&mut self.from_terms, doc_id, &from_tokens);
        add_terms(&mut self.to_terms, doc_id, &to_tokens);
        let doc_id_value = doc.id.clone();
        self.slots.push(Slot {
            doc,
            deleted: false,
            length: u32::try_from(length).unwrap_or(u32::MAX),
        });
        self.by_id.insert(doc_id_value, doc_id);
        self.active_docs += 1;
        self.total_length += length as u64;
    }

    pub fn delete(&mut self, id: &str) {
        if let Some(doc_id) = self.by_id.remove(id) {
            if let Some(slot) = self.slots.get_mut(doc_id as usize) {
                if !slot.deleted {
                    slot.deleted = true;
                    self.active_docs = self.active_docs.saturating_sub(1);
                    self.total_length = self.total_length.saturating_sub(u64::from(slot.length));
                }
            }
        }
    }

    pub fn update_flags(&mut self, id: &str, flags: u64) {
        if let Some(doc_id) = self.by_id.get(id) {
            if let Some(slot) = self.slots.get_mut(*doc_id as usize) {
                slot.doc.flags = flags;
            }
        }
    }

    pub fn move_message(&mut self, id: &str, account_id: &str, mailbox: &str) {
        if let Some(doc_id) = self.by_id.get(id) {
            if let Some(slot) = self.slots.get_mut(*doc_id as usize) {
                slot.doc.account_id = account_id.to_string();
                slot.doc.mailbox = mailbox.to_string();
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<&Doc> {
        let doc_id = self.by_id.get(id)?;
        let slot = self.slots.get(*doc_id as usize)?;
        if slot.deleted { None } else { Some(&slot.doc) }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Doc> {
        self.slots
            .iter()
            .filter(|slot| !slot.deleted)
            .map(|slot| &slot.doc)
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchHit> {
        if self.slots.is_empty() {
            return Vec::new();
        }
        let mut constraints: Vec<HashSet<u32>> = Vec::new();
        let mut scored_terms: Vec<(TermSource, String)> = Vec::new();

        if let Some(text) = query.text.as_deref() {
            for term in tokenize(text) {
                let mut docs = HashSet::new();
                collect_docs(&self.subject_terms, &term, &mut docs);
                collect_docs(&self.body_terms, &term, &mut docs);
                if docs.is_empty() {
                    return Vec::new();
                }
                constraints.push(docs);
                scored_terms.push((TermSource::Text, term));
            }
        }
        if let Some(text) = query.subject.as_deref() {
            for term in tokenize(text) {
                let docs = docs_for(&self.subject_terms, &term);
                if docs.is_empty() {
                    return Vec::new();
                }
                constraints.push(docs);
                scored_terms.push((TermSource::Subject, term));
            }
        }
        if let Some(text) = query.body.as_deref() {
            for term in tokenize(text) {
                let docs = docs_for(&self.body_terms, &term);
                if docs.is_empty() {
                    return Vec::new();
                }
                constraints.push(docs);
                scored_terms.push((TermSource::Body, term));
            }
        }
        if let Some(text) = query.from.as_deref() {
            for term in tokenize(text) {
                let docs = docs_for(&self.from_terms, &term);
                if docs.is_empty() {
                    return Vec::new();
                }
                constraints.push(docs);
                scored_terms.push((TermSource::From, term));
            }
        }

        let candidates: Vec<u32> = if constraints.is_empty() {
            self.slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| !slot.deleted)
                .map(|(index, _)| index as u32)
                .collect()
        } else {
            let mut smallest = constraints
                .iter()
                .min_by_key(|set| set.len())
                .cloned()
                .unwrap_or_default();
            for set in &constraints {
                smallest.retain(|doc| set.contains(doc));
                if smallest.is_empty() {
                    return Vec::new();
                }
            }
            smallest.into_iter().collect()
        };

        let avgdl = if self.active_docs == 0 {
            1.0
        } else {
            self.total_length as f64 / self.active_docs as f64
        };
        let scored_terms = scored_terms
            .iter()
            .map(|(source, term)| {
                let df = df_for(*source, self, term).max(1) as f64;
                let idf = ((self.active_docs as f64 - df + 0.5) / (df + 0.5) + 1.0).ln();
                (*source, term.clone(), idf)
            })
            .collect::<Vec<_>>();
        let score_one = |doc_id: u32| -> Option<(u32, u64, i64)> {
            let slot = self.slots.get(doc_id as usize)?;
            if slot.deleted && !query.include_deleted {
                return None;
            }
            if let Some(account) = &query.account_id {
                if &slot.doc.account_id != account {
                    return None;
                }
            }
            if let Some(mailbox) = &query.mailbox {
                if &slot.doc.mailbox != mailbox {
                    return None;
                }
            }
            if !query.include_deleted && slot.doc.flags & tide_core::flags::DELETED != 0 {
                return None;
            }
            let score = if scored_terms.is_empty() {
                1.0
            } else {
                let mut value = 0.0;
                for (source, term, idf) in &scored_terms {
                    let (term_frequency, weight) = match source {
                        TermSource::Subject => {
                            (tf(&self.subject_terms, term, doc_id), SUBJECT_WEIGHT)
                        }
                        TermSource::Body => (tf(&self.body_terms, term, doc_id), BODY_WEIGHT),
                        TermSource::From => (tf(&self.from_terms, term, doc_id), FROM_WEIGHT),
                        TermSource::Text => (
                            tf(&self.subject_terms, term, doc_id)
                                + tf(&self.body_terms, term, doc_id),
                            1.0,
                        ),
                    };
                    if term_frequency == 0 {
                        continue;
                    }
                    let dl = f64::from(slot.length.max(1));
                    let denominator =
                        f64::from(term_frequency) + 1.2 * (1.0 - 0.75 + 0.75 * dl / avgdl.max(1.0));
                    value += weight * idf * (f64::from(term_frequency) * 2.2) / denominator;
                }
                value
            };
            Some((doc_id, (score * 1000.0).round() as u64, slot.doc.date))
        };
        let mut scored: Vec<(u32, u64, i64)> = if candidates.len() >= 4096 {
            candidates
                .par_iter()
                .filter_map(|doc_id| score_one(*doc_id))
                .collect()
        } else {
            candidates
                .iter()
                .filter_map(|doc_id| score_one(*doc_id))
                .collect()
        };

        let comparator = |left: &(u32, u64, i64), right: &(u32, u64, i64)| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| right.2.cmp(&left.2))
                .then_with(|| left.0.cmp(&right.0))
        };
        let limit = query.limit.clamp(1, MAX_LIMIT);
        let keep = (query.offset.saturating_add(limit)).min(scored.len());
        if scored.len() > keep && keep > 0 {
            scored.select_nth_unstable_by(keep, comparator);
            scored.truncate(keep);
        }
        scored.sort_by(comparator);
        let scored_terms_plain = scored_terms
            .iter()
            .map(|(source, term, _)| (*source, term.clone()))
            .collect::<Vec<_>>();
        scored
            .into_iter()
            .skip(query.offset)
            .take(limit)
            .filter_map(|(doc_id, score, _)| {
                let slot = self.slots.get(doc_id as usize)?;
                Some(SearchHit {
                    id: slot.doc.id.clone(),
                    account_id: slot.doc.account_id.clone(),
                    mailbox: slot.doc.mailbox.clone(),
                    subject: slot.doc.subject.clone(),
                    from: slot.doc.from.clone(),
                    date: slot.doc.date,
                    flags: slot.doc.flags,
                    score,
                    snippet: make_snippet(&slot.doc, &scored_terms_plain),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
enum TermSource {
    Subject,
    Body,
    From,
    Text,
}

fn df_for(source: TermSource, index: &SearchIndex, term: &str) -> usize {
    match source {
        TermSource::Subject => index.subject_terms.get(term).map_or(0, Vec::len),
        TermSource::Body => index.body_terms.get(term).map_or(0, Vec::len),
        TermSource::From => index.from_terms.get(term).map_or(0, Vec::len),
        TermSource::Text => {
            let mut docs = HashSet::new();
            collect_docs(&index.subject_terms, term, &mut docs);
            collect_docs(&index.body_terms, term, &mut docs);
            docs.len()
        }
    }
}

fn add_terms(target: &mut Postings, doc_id: u32, tokens: &[String]) {
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for token in tokens {
        *counts.entry(token.as_str()).or_insert(0) += 1;
    }
    for (term, tf) in counts {
        target.push(term, Posting { doc: doc_id, tf });
    }
}

fn tf(map: &Postings, term: &str, doc_id: u32) -> u32 {
    map.get(term)
        .and_then(|postings| {
            postings
                .binary_search_by_key(&doc_id, |posting| posting.doc)
                .ok()
                .map(|index| postings[index].tf)
        })
        .unwrap_or(0)
}

fn docs_for(map: &Postings, term: &str) -> HashSet<u32> {
    let mut docs = HashSet::new();
    collect_docs(map, term, &mut docs);
    docs
}

fn collect_docs(map: &Postings, term: &str, out: &mut HashSet<u32>) {
    if let Some(postings) = map.get(term) {
        out.extend(postings.iter().map(|posting| posting.doc));
    }
}

fn make_snippet(doc: &Doc, terms: &[(TermSource, String)]) -> String {
    let needle = terms.iter().find_map(|(source, term)| match source {
        TermSource::Subject => {
            if doc.subject.to_lowercase().contains(term) {
                Some(term.as_str())
            } else {
                None
            }
        }
        TermSource::Body | TermSource::Text => {
            if doc.body.to_lowercase().contains(term) {
                Some(term.as_str())
            } else {
                None
            }
        }
        TermSource::From => None,
    });
    let Some(needle) = needle else {
        return truncate_chars(&doc.body, 180);
    };
    let lower = doc.body.to_lowercase();
    let Some(byte_pos) = lower.find(needle) else {
        return truncate_chars(&doc.body, 180);
    };
    let chars_before = doc.body[..byte_pos].chars().count();
    let start_chars = chars_before.saturating_sub(60);
    let start = char_to_byte(&doc.body, start_chars);
    let end = char_to_byte(&doc.body, start_chars + 180);
    let mut snippet = doc.body[start..end].trim().to_string();
    if start > 0 {
        snippet.insert(0, '…');
    }
    if end < doc.body.len() {
        snippet.push('…');
    }
    snippet
}

fn truncate_chars(value: &str, max: usize) -> String {
    let mut result: String = value.chars().take(max).collect();
    if value.chars().count() > max {
        result.push('…');
    }
    result
}

fn char_to_byte(value: &str, char_index: usize) -> usize {
    value
        .char_indices()
        .nth(char_index)
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}

fn tokenize(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    for word in value.unicode_words() {
        let lower = word.to_lowercase();
        let trimmed = lower.trim_matches(|character: char| {
            !character.is_alphanumeric() && character != '_' && character != '-'
        });
        if trimmed.len() < 2 || trimmed.len() > 64 || is_stopword(trimmed) {
            continue;
        }
        let stemmed = stem_cached(trimmed, trimmed.chars().any(is_cyrillic));
        if !stemmed.is_empty() {
            result.push(stemmed);
        }
    }
    result
}

fn stem_cached(token: &str, cyrillic: bool) -> String {
    static ENGLISH: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    static RUSSIAN: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    let cache = if cyrillic {
        RUSSIAN.get_or_init(|| RwLock::new(HashMap::new()))
    } else {
        ENGLISH.get_or_init(|| RwLock::new(HashMap::new()))
    };
    if let Some(value) = cache.read().get(token) {
        return value.clone();
    }
    let value = if cyrillic {
        russian_stemmer().stem(token).into_owned()
    } else {
        english_stemmer().stem(token).into_owned()
    };
    let mut cache = cache.write();
    if cache.len() > 100_000 {
        cache.clear();
    }
    cache.insert(token.to_string(), value.clone());
    value
}

fn is_cyrillic(character: char) -> bool {
    matches!(character, '\u{0400}'..='\u{04FF}')
}

fn english_stemmer() -> &'static Stemmer {
    static STEMMER: OnceLock<Stemmer> = OnceLock::new();
    STEMMER.get_or_init(|| Stemmer::create(Algorithm::English))
}

fn russian_stemmer() -> &'static Stemmer {
    static STEMMER: OnceLock<Stemmer> = OnceLock::new();
    STEMMER.get_or_init(|| Stemmer::create(Algorithm::Russian))
}

fn is_stopword(word: &str) -> bool {
    const WORDS: &[&str] = &[
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "he",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "that",
        "the",
        "to",
        "was",
        "were",
        "will",
        "with",
        "this",
        "these",
        "those",
        "or",
        "not",
        "but",
        "you",
        "your",
        "we",
        "our",
        "и",
        "в",
        "во",
        "не",
        "что",
        "он",
        "на",
        "я",
        "с",
        "со",
        "как",
        "а",
        "то",
        "все",
        "она",
        "так",
        "его",
        "но",
        "да",
        "ты",
        "к",
        "у",
        "же",
        "вы",
        "за",
        "бы",
        "по",
        "только",
        "ее",
        "мне",
        "было",
        "вот",
        "от",
        "меня",
        "еще",
        "нет",
        "о",
        "из",
        "ему",
        "теперь",
        "когда",
        "даже",
        "ну",
        "вдруг",
        "ли",
        "если",
        "уже",
        "или",
        "ни",
        "быть",
        "был",
        "него",
        "до",
        "вас",
        "нибудь",
        "опять",
        "уж",
        "вам",
        "ведь",
        "там",
        "потом",
        "себя",
        "ничего",
        "ей",
        "может",
        "они",
        "тут",
        "где",
        "есть",
        "надо",
        "ней",
        "для",
        "мы",
        "тебя",
        "их",
        "чем",
        "была",
        "сам",
        "чтоб",
        "без",
        "будто",
        "чего",
        "раз",
        "тоже",
        "себе",
        "под",
        "будет",
        "ж",
        "тогда",
        "кто",
        "этот",
        "того",
        "потому",
        "этого",
        "какой",
        "совсем",
        "ним",
        "здесь",
        "этом",
        "один",
        "почти",
        "мой",
        "тем",
        "чтобы",
        "нее",
        "сейчас",
        "были",
        "куда",
        "зачем",
        "всех",
        "никогда",
        "можно",
        "при",
        "наконец",
        "два",
        "об",
        "другой",
        "хоть",
        "после",
        "над",
        "больше",
        "тот",
        "через",
        "эти",
        "нас",
        "про",
        "всего",
        "них",
        "какая",
        "много",
        "разве",
        "три",
        "эту",
        "моя",
        "впрочем",
        "хорошо",
        "свою",
        "этой",
        "перед",
        "иногда",
        "лучше",
        "чуть",
        "том",
        "нельзя",
        "такой",
        "им",
        "более",
        "всегда",
        "конечно",
        "всю",
        "между",
    ];
    WORDS.contains(&word)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardedIndex {
    shards: Vec<SearchIndex>,
}

impl Default for ShardedIndex {
    fn default() -> Self {
        Self::new(16)
    }
}

impl ShardedIndex {
    pub fn new(shards: usize) -> Self {
        Self {
            shards: (0..shards.max(1)).map(|_| SearchIndex::new()).collect(),
        }
    }

    fn shard_for(&self, account_id: &str) -> usize {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in account_id.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (hash as usize) % self.shards.len()
    }

    pub fn insert(&mut self, message: &Message) {
        let shard = self.shard_for(&message.account_id);
        self.shards[shard].insert(message);
    }

    pub fn delete(&mut self, id: &str) {
        for shard in &mut self.shards {
            if shard.by_id.contains_key(id) {
                shard.delete(id);
                return;
            }
        }
    }

    pub fn update_flags(&mut self, id: &str, flags: u64) {
        for shard in &mut self.shards {
            if shard.by_id.contains_key(id) {
                shard.update_flags(id, flags);
                return;
            }
        }
    }

    pub fn move_message(&mut self, id: &str, account_id: &str, mailbox: &str) {
        let target = self.shard_for(account_id);
        let mut moved = None;
        for (index, shard) in self.shards.iter_mut().enumerate() {
            if shard.by_id.contains_key(id) {
                if index == target {
                    shard.move_message(id, account_id, mailbox);
                    return;
                }
                if let Some(doc) = shard.get(id).cloned() {
                    shard.delete(id);
                    moved = Some(doc);
                }
                break;
            }
        }
        if let Some(mut doc) = moved {
            doc.account_id = account_id.to_string();
            doc.mailbox = mailbox.to_string();
            self.shards[target].insert_doc(doc);
        }
    }

    pub fn get(&self, id: &str) -> Option<&Doc> {
        self.shards.iter().find_map(|shard| shard.get(id))
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(SearchIndex::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn ids(&self) -> Vec<String> {
        self.shards
            .iter()
            .flat_map(|shard| shard.iter().map(|doc| doc.id.clone()))
            .collect()
    }

    pub fn docs_for_account(&self, account_id: &str) -> Vec<Doc> {
        self.shards[self.shard_for(account_id)]
            .iter()
            .filter(|doc| doc.account_id == account_id)
            .cloned()
            .collect()
    }

    pub fn ids_in_folder(&self, account_id: &str, mailbox: &str) -> Vec<String> {
        self.shards[self.shard_for(account_id)]
            .iter()
            .filter(|doc| doc.account_id == account_id && doc.mailbox == mailbox)
            .map(|doc| doc.id.clone())
            .collect()
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchHit> {
        if let Some(account) = &query.account_id {
            return self.shards[self.shard_for(account)].search(query);
        }
        let limit = query.limit.clamp(1, MAX_LIMIT);
        let mut hits = self
            .shards
            .par_iter()
            .flat_map_iter(|shard| {
                let mut shard_query = query.clone();
                shard_query.limit = (query.offset + limit).min(MAX_LIMIT);
                shard_query.offset = 0;
                shard.search(&shard_query)
            })
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.date.cmp(&left.date))
                .then_with(|| left.id.cmp(&right.id))
        });
        hits.into_iter().skip(query.offset).take(limit).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tide_core::{Address, Message};

    fn message(id: &str, account: &str, subject: &str, body: &str) -> Message {
        Message {
            id: id.into(),
            account_id: account.into(),
            mailbox: "INBOX".into(),
            subject: subject.into(),
            body_text: body.into(),
            from: vec![Address {
                email: "sender@example.com".into(),
                name: Some("Sender".into()),
            }],
            date: 1_700_000_000_000,
            ..Message::default()
        }
    }

    #[test]
    fn finds_subject_and_body_terms() {
        let mut index = SearchIndex::new();
        index.insert(&message("1", "a", "Quarterly report", "revenue growth"));
        index.insert(&message("2", "a", "Lunch", "quarterly planning"));
        index.insert(&message("3", "b", "Quarterly report", "other account"));

        let hits = index.search(&SearchQuery::new().account("a").text("quarterly"));
        assert_eq!(hits.len(), 2);
        let subject_hits = index.search(&SearchQuery::new().account("a").subject("report"));
        assert_eq!(subject_hits.len(), 1);
        assert_eq!(subject_hits[0].id, "1");
    }

    #[test]
    fn respects_account_and_mailbox_filters() {
        let mut index = SearchIndex::new();
        index.insert(&message("1", "a", "hello", "world"));
        index.insert(&message("2", "b", "hello", "world"));
        let hits = index.search(&SearchQuery::new().account("b").text("hello"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "2");
        let hits = index.search(&SearchQuery::new().mailbox("INBOX").text("hello"));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn sharded_index_routes_and_moves_accounts() {
        let mut index = ShardedIndex::new(4);
        index.insert(&message("1", "alice", "invoice", "body"));
        index.insert(&message("2", "bob", "invoice", "body"));
        index.insert(&message("3", "carol", "other", "body"));
        assert_eq!(index.len(), 3);
        assert_eq!(
            index
                .search(&SearchQuery::new().account("alice").text("invoice"))
                .len(),
            1
        );
        assert_eq!(index.search(&SearchQuery::new().text("invoice")).len(), 2);
        index.move_message("1", "bob", "INBOX");
        assert_eq!(
            index
                .search(&SearchQuery::new().account("alice").text("invoice"))
                .len(),
            0
        );
        assert_eq!(
            index
                .search(&SearchQuery::new().account("bob").text("invoice"))
                .len(),
            2
        );
    }

    #[test]
    fn delete_hides_message() {
        let mut index = SearchIndex::new();
        index.insert(&message("1", "a", "hello", "world"));
        index.delete("1");
        assert!(index.get("1").is_none());
        assert!(index.search(&SearchQuery::new().text("hello")).is_empty());
    }

    #[test]
    fn replaces_duplicate_id() {
        let mut index = SearchIndex::new();
        index.insert(&message("1", "a", "old subject", "old body"));
        index.insert(&message("1", "a", "new subject", "new body"));
        assert_eq!(index.len(), 1);
        let hits = index.search(&SearchQuery::new().text("new"));
        assert_eq!(hits.len(), 1);
        assert!(index.search(&SearchQuery::new().text("old")).is_empty());
    }
}
