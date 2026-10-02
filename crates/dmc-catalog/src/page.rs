pub const DEFAULT_PAGE_LIMIT: u32 = 500;
pub const MAX_PAGE_LIMIT: u32 = 2_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub name_filter: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

impl<T> CatalogPage<T> {
    pub fn full(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
            truncated: false,
        }
    }
}

/// Keyset pagination by stable name key (lexicographic).
pub fn page_by_name<T, F>(
    mut items: Vec<T>,
    query: &PageQuery,
    name_of: F,
) -> CatalogPage<T>
where
    F: Fn(&T) -> &str,
{
    if let Some(filter) = query.name_filter.as_deref() {
        let f = filter.to_ascii_lowercase();
        items.retain(|item| name_of(item).to_ascii_lowercase().contains(&f));
    }
    items.sort_by(|a, b| name_of(a).cmp(name_of(b)));
    if let Some(cursor) = query.cursor.as_deref() {
        items.retain(|item| name_of(item) > cursor);
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT) as usize;
    let truncated = items.len() > limit;
    if truncated {
        items.truncate(limit);
    }
    let next_cursor = if truncated {
        items.last().map(|item| name_of(item).to_string())
    } else {
        None
    };
    CatalogPage {
        items,
        next_cursor,
        truncated,
    }
}
