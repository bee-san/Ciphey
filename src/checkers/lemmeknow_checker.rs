use super::checker_type::{Check, Checker};
use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::{Data, Identifier};
use rayon::prelude::*;
use std::sync::Once;

/// Patterns rarer than this are ignored: they match too much ordinary text.
const MIN_RARITY: f32 = 0.1;

/// Tags that split LemmeKnow's patterns into [`warm_up`] tasks of similar compile time.
/// Discord, URL and YouTube each hold one of the three slowest patterns to compile.
const WARM_UP_TAGS: [&str; 5] = ["Discord", "URL", "YouTube", "Credentials", "Finance"];

/// Rarity bands that split the [`warm_up`] tasks further. LemmeKnow 0.8 only has
/// rarities 0.2, 0.3, 0.4, 0.5, 0.7, 0.8 and 1, so the bands leave no pattern out.
const WARM_UP_BANDS: [(f32, f32); 2] = [(1.0, 1.0), (MIN_RARITY, 0.99)];

/// Starts compiling LemmeKnow's regexes on the rayon pool and returns at once.
///
/// LemmeKnow compiles each of its ~120 regexes the first time `identify` tries it, so
/// the first check in a process compiles all of them one after another: about 70 ms,
/// 30 ms of it for the Discord Webhook pattern alone. That is most of a `ciphey` run
/// on a new input. Each regex is a separate lazy static, and `identify` only tries the
/// patterns its filter lets through, so each task here is an [`Identifier`] whose
/// rarity and tag filter selects one share of the patterns, run on "". The shares
/// don't overlap and together cover every pattern the checker uses, so the slowest
/// pattern, not the sum of all of them, sets how long compiling takes. A check that
/// needs a pattern no task has compiled yet compiles it itself, as before: this only
/// changes when and on which thread the patterns are compiled, not what is matched.
pub fn warm_up() {
    static STARTED: Once = Once::new();
    STARTED.call_once(|| {
        rayon::spawn(|| {
            warm_up_tasks().par_iter().for_each(|identifier| {
                identifier.identify("");
            });
        });
    });
}

/// The [`warm_up`] tasks: for each rarity band, one task per tag in [`WARM_UP_TAGS`]
/// (skipping patterns an earlier tag's task takes) and one for the patterns with none
/// of those tags.
fn warm_up_tasks() -> Vec<Identifier> {
    let mut tasks = Vec::new();
    for (min, max) in WARM_UP_BANDS {
        let band = |include: &[&str], exclude: &[&str]| Identifier {
            min_rarity: min,
            max_rarity: max,
            tags: include.iter().map(|tag| tag.to_string()).collect(),
            exclude_tags: exclude.iter().map(|tag| tag.to_string()).collect(),
            boundaryless: false,
            file_support: false,
        };
        for (i, tag) in WARM_UP_TAGS.iter().enumerate() {
            tasks.push(band(&[tag], &WARM_UP_TAGS[..i]));
        }
        tasks.push(band(&[], &WARM_UP_TAGS));
    }
    tasks
}

/// The LemmeKnow Checker checks if the text matches a known Regex pattern.
/// This is the struct for it.
pub struct LemmeKnow;

impl Check for Checker<LemmeKnow> {
    fn new() -> Self {
        Checker {
            // TODO: Update fields with proper values
            name: "LemmeKnow Checker",
            description: "Uses LemmeKnow to check for regex matches",
            link: "https://swanandx.github.io/lemmeknow-frontend/",
            tags: vec!["lemmeknow", "regex"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default().min_rarity(MIN_RARITY),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let lemmeknow_result = self.lemmeknow_config.identify(text);
        let mut is_identified = false;
        let mut description = "".to_string();
        if !lemmeknow_result.is_empty() {
            is_identified = true;
            description = format_data_result(&lemmeknow_result[0].data)
        }

        CheckResult {
            is_identified,
            text: text.to_owned(),
            checker_name: self.name,
            checker_description: self.description,
            // Returns a vector of matches
            description,
            link: self.link,
        }
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// Formats the data result to a string
/// This is used to display the result in the UI
fn format_data_result(input: &Data) -> String {
    input.name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::checker_type::{Check, Checker};
    use gibberish_or_not::Sensitivity;

    #[test]
    fn test_url_exact_match() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("https://google.com").is_identified);
    }

    #[test]
    fn test_url_with_extra_text_fails() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(
            !checker
                .check("https://google.com and some text")
                .is_identified
        );
    }

    #[test]
    fn test_ip_exact_match() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("192.168.1.1").is_identified);
    }

    #[test]
    fn test_ip_with_extra_text_fails() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(!checker.check("IP is 192.168.1.1").is_identified);
    }

    #[test]
    fn test_s3_path() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(checker.check("s3://bucket/path/key").is_identified);
    }

    // Lemmeknow can only match if its an EXACT match
    // So this should fail
    #[test]
    fn test_bitcoin_with_extra_text_fails() {
        let checker = Checker::<LemmeKnow>::new().with_sensitivity(Sensitivity::Low);
        assert!(
            !checker
                .check("BTC address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
                .is_identified
        );
    }

    /// Texts LemmeKnow identifies, across rarities and tags, including the slowest
    /// patterns to compile (Discord Webhook, URL, YouTube Video).
    const IDENTIFIABLE: [&str; 11] = [
        "https://google.com",
        "192.168.1.1",
        "bee@skerritt.blog",
        "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcd",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "UC11L3JDgDQMyH8iolKkVZ4w",
        "4111111111111111",
        "s3://bucket/path/key",
        "8888888888",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "arn:aws:iam::123456789012:user/bee",
    ];

    #[test]
    fn warm_up_tasks_split_the_checkers_patterns_without_overlap() {
        // Each pattern the checker can match is selected by exactly one warm-up task, so
        // the tasks compile every pattern the checker uses, each of them once.
        let checker = Checker::<LemmeKnow>::new();
        let tasks = warm_up_tasks();
        for text in IDENTIFIABLE {
            let mut expected: Vec<&str> = checker
                .lemmeknow_config
                .identify(text)
                .iter()
                .map(|m| m.data.name)
                .collect();
            assert!(!expected.is_empty(), "LemmeKnow should identify {text:?}");
            let mut from_tasks: Vec<&str> = tasks
                .iter()
                .flat_map(|task| task.identify(text))
                .map(|m| m.data.name)
                .collect();
            expected.sort_unstable();
            from_tasks.sort_unstable();
            assert_eq!(from_tasks, expected, "patterns matching {text:?}");
        }
    }

    #[test]
    fn checks_after_warm_up_match_as_before() {
        warm_up();
        // A second call does nothing
        warm_up();
        let checker = Checker::<LemmeKnow>::new();
        for text in IDENTIFIABLE {
            assert!(checker.check(text).is_identified, "{text:?}");
        }
        assert!(!checker.check("hello my name is bee").is_identified);
    }
}
