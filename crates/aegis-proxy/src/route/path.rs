use std::collections::HashMap;

/// A prefix-trie that resolves the **longest matching prefix** for a given
/// path.  Each node may carry a value `V` if it represents the end of an
/// inserted pattern.
///
/// Segments are split on `/`.  A trailing `/` on the pattern is normalised
/// away so that `/api/v1/` and `/api/v1` are equivalent.
#[derive(Debug)]
pub struct PathTrie<V> {
    value: Option<V>,
    children: HashMap<String, PathTrie<V>>,
}

impl<V> Default for PathTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> PathTrie<V> {
    pub fn new() -> Self {
        Self {
            value: None,
            children: HashMap::new(),
        }
    }

    /// Insert `value` under `pattern`.
    ///
    /// `pattern` is split on `/`; empty segments (from leading or trailing
    /// slashes) are ignored, so `/api/v1/` becomes `["api", "v1"]`.
    pub fn insert(&mut self, pattern: &str, value: V) {
        let segments = Self::split(pattern);
        let mut node = self;
        for seg in segments {
            node = node
                .children
                .entry(seg.to_owned())
                .or_default();
        }
        node.value = Some(value);
    }

    /// Find the value associated with the **longest prefix** that matches
    /// `path`.  Returns `None` only if the root itself has no value and no
    /// prefix matches.
    ///
    /// Use this for **runtime resolution**. For build-time same-path
    /// lookups (e.g. merging method-specific routes that share a path),
    /// use [`find_exact`](Self::find_exact) instead — `find` would
    /// incorrectly return an ancestor's value, which historically caused
    /// the catch-all to bleed into more specific paths' index lists.
    pub fn find(&self, path: &str) -> Option<&V> {
        let segments = Self::split(path);
        let mut node = self;
        let mut best = node.value.as_ref();

        for seg in segments {
            match node.children.get(seg) {
                Some(child) => {
                    node = child;
                    if node.value.is_some() {
                        best = node.value.as_ref();
                    }
                }
                None => break,
            }
        }

        best
    }

    /// Find the value at the **exact** path. Returns `None` if no entry
    /// has been inserted at this exact node, even if an ancestor has a
    /// value. Use this only for build-time same-path merges — runtime
    /// resolution always uses [`find`](Self::find).
    pub fn find_exact(&self, path: &str) -> Option<&V> {
        let segments = Self::split(path);
        let mut node = self;
        for seg in segments {
            match node.children.get(seg) {
                Some(child) => node = child,
                None => return None,
            }
        }
        node.value.as_ref()
    }

    /// Walk the trie along `path` and emit every value encountered,
    /// **longest prefix first**. Used by route resolution to support
    /// method-filter fallthrough: if the longest-prefix node has only
    /// method-filtered routes that don't match, the resolver retries
    /// at progressively shorter prefixes until something matches —
    /// e.g. `PUT /api` falls through to the catch-all `/` when the
    /// only routes at `/api` are `GET` and `POST`.
    pub fn find_all_prefixes(&self, path: &str) -> Vec<&V> {
        let segments = Self::split(path);
        let mut node = self;
        let mut hits: Vec<&V> = Vec::new();
        if let Some(v) = node.value.as_ref() {
            hits.push(v);
        }
        for seg in segments {
            match node.children.get(seg) {
                Some(child) => {
                    node = child;
                    if let Some(v) = node.value.as_ref() {
                        hits.push(v);
                    }
                }
                None => break,
            }
        }
        hits.reverse(); // longest first
        hits
    }

    fn split(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_returns_none() {
        let trie: PathTrie<&str> = PathTrie::new();
        assert!(trie.find("/anything").is_none());
    }

    #[test]
    fn root_catch_all() {
        let mut trie = PathTrie::new();
        trie.insert("/", "root");
        assert_eq!(trie.find("/"), Some(&"root"));
        assert_eq!(trie.find("/anything"), Some(&"root"));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut trie = PathTrie::new();
        trie.insert("/api/", "api");
        trie.insert("/api/v1/", "api-v1");

        assert_eq!(trie.find("/api/v1/users"), Some(&"api-v1"));
        assert_eq!(trie.find("/api/v2/users"), Some(&"api"));
        assert_eq!(trie.find("/api/"), Some(&"api"));
    }

    #[test]
    fn exact_path_match() {
        let mut trie = PathTrie::new();
        trie.insert("/health", "health");
        assert_eq!(trie.find("/health"), Some(&"health"));
    }

    #[test]
    fn no_match_falls_through() {
        let mut trie = PathTrie::new();
        trie.insert("/api/", "api");
        assert!(trie.find("/other/path").is_none());
    }

    #[test]
    fn trailing_slash_normalised() {
        let mut trie = PathTrie::new();
        trie.insert("/api/v1/", "with-slash");

        assert_eq!(trie.find("/api/v1"), Some(&"with-slash"));
        assert_eq!(trie.find("/api/v1/"), Some(&"with-slash"));
        assert_eq!(trie.find("/api/v1/users"), Some(&"with-slash"));
    }

    #[test]
    fn multiple_routes_coexist() {
        let mut trie = PathTrie::new();
        trie.insert("/", "root");
        trie.insert("/api/", "api");
        trie.insert("/api/v1/", "api-v1");
        trie.insert("/static/", "static");
        trie.insert("/health", "health");

        assert_eq!(trie.find("/"), Some(&"root"));
        assert_eq!(trie.find("/api/v1/users"), Some(&"api-v1"));
        assert_eq!(trie.find("/api/v2/users"), Some(&"api"));
        assert_eq!(trie.find("/static/css/main.css"), Some(&"static"));
        assert_eq!(trie.find("/health"), Some(&"health"));
        assert_eq!(trie.find("/unknown"), Some(&"root"));
    }

    #[test]
    fn deeply_nested_path() {
        let mut trie = PathTrie::new();
        trie.insert("/a/b/c/d/e", "deep");
        assert_eq!(trie.find("/a/b/c/d/e"), Some(&"deep"));
        assert_eq!(trie.find("/a/b/c/d/e/f"), Some(&"deep"));
        assert!(trie.find("/a/b/c/d").is_none());
    }

    #[test]
    fn overwrite_existing_value() {
        let mut trie = PathTrie::new();
        trie.insert("/api", "first");
        trie.insert("/api", "second");
        assert_eq!(trie.find("/api"), Some(&"second"));
    }

    #[test]
    fn find_exact_returns_value_at_exact_node() {
        let mut trie = PathTrie::new();
        trie.insert("/api", "api");
        assert_eq!(trie.find_exact("/api"), Some(&"api"));
        assert_eq!(trie.find_exact("/api/"), Some(&"api"));
    }

    #[test]
    fn find_exact_returns_none_for_descendants() {
        let mut trie = PathTrie::new();
        trie.insert("/api", "api");
        // `/api/v2` walks past `/api`'s node but `v2` child doesn't
        // exist — find_exact must NOT fall back to the ancestor value
        // (this is the bug `find` would mask at build time).
        assert_eq!(trie.find_exact("/api/v2"), None);
    }

    #[test]
    fn find_exact_returns_none_for_missing_root_value() {
        let mut trie = PathTrie::new();
        trie.insert("/api", "api");
        // Root `/` has no value of its own — find_exact must return None
        // even though the catch-all `find` would have walked here.
        assert_eq!(trie.find_exact("/"), None);
    }

    #[test]
    fn find_exact_distinguishes_root_from_descendants() {
        let mut trie = PathTrie::new();
        trie.insert("/", "root");
        trie.insert("/api", "api");
        assert_eq!(trie.find_exact("/"), Some(&"root"));
        assert_eq!(trie.find_exact("/api"), Some(&"api"));
        assert_eq!(trie.find_exact("/other"), None);
        assert_eq!(trie.find_exact("/api/v2"), None);
    }

    #[test]
    fn find_exact_empty_trie_returns_none() {
        let trie: PathTrie<&str> = PathTrie::new();
        assert_eq!(trie.find_exact("/anything"), None);
        assert_eq!(trie.find_exact("/"), None);
    }

    #[test]
    fn find_all_prefixes_returns_longest_first() {
        let mut trie = PathTrie::new();
        trie.insert("/", "root");
        trie.insert("/api", "api");
        trie.insert("/api/v2", "api-v2");

        let hits = trie.find_all_prefixes("/api/v2/users");
        assert_eq!(hits, vec![&"api-v2", &"api", &"root"]);

        let hits = trie.find_all_prefixes("/api/v3/users");
        assert_eq!(hits, vec![&"api", &"root"]);

        let hits = trie.find_all_prefixes("/totally/unrelated");
        assert_eq!(hits, vec![&"root"]);
    }

    #[test]
    fn find_all_prefixes_empty_when_no_match() {
        let mut trie = PathTrie::new();
        trie.insert("/api", "api"); // no root value
        let hits = trie.find_all_prefixes("/totally/unrelated");
        assert!(hits.is_empty());
    }
}
