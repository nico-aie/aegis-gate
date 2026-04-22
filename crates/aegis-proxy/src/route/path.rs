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
}
