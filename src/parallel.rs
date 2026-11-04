//! Parallel iterators where there are threads.
//!
//! On native targets this is rayon's prelude. WebAssembly has no threads: the search runs
//! on the caller's thread (see docs/wasm.md), so there the rayon methods the library uses
//! (`par_iter`, `into_par_iter`, `flat_map_iter`, `find_map_first` and
//! `try_for_each_with`) are plain [`Iterator`]s that run the work in order on the calling
//! thread. They return what rayon's do: the first match in order, the items in order.

#[cfg(not(target_family = "wasm"))]
pub(crate) use rayon::prelude::*;

#[cfg(target_family = "wasm")]
pub(crate) use sequential::*;

/// The sequential stand-ins for rayon's traits. Natively they are only built for the tests
/// below, which check that they give what rayon gives.
#[cfg(any(target_family = "wasm", test))]
mod sequential {
    /// `par_iter()` on a slice (and so on a `Vec`): its `iter()`.
    pub(crate) trait IntoParallelRefIterator<'data> {
        /// The iterator
        type Iter: Iterator;
        /// The items in order
        fn par_iter(&'data self) -> Self::Iter;
    }

    impl<'data, T: 'data> IntoParallelRefIterator<'data> for [T] {
        type Iter = std::slice::Iter<'data, T>;
        fn par_iter(&'data self) -> Self::Iter {
            self.iter()
        }
    }

    /// `into_par_iter()` on a borrowed `Vec`: its `iter()`.
    pub(crate) trait IntoParallelIterator {
        /// The iterator
        type Iter: Iterator;
        /// The items in order
        fn into_par_iter(self) -> Self::Iter;
    }

    impl<'data, T> IntoParallelIterator for &'data Vec<T> {
        type Iter = std::slice::Iter<'data, T>;
        fn into_par_iter(self) -> Self::Iter {
            self.iter()
        }
    }

    /// The `ParallelIterator` methods the library uses that `Iterator` has no method of
    /// the same name for.
    pub(crate) trait ParallelIterator: Iterator + Sized {
        /// `flat_map`
        fn flat_map_iter<U, F>(self, f: F) -> std::iter::FlatMap<Self, U, F>
        where
            U: IntoIterator,
            F: FnMut(Self::Item) -> U,
        {
            self.flat_map(f)
        }

        /// `find_map`: the first item `f` maps to `Some`
        fn find_map_first<B, F>(mut self, f: F) -> Option<B>
        where
            F: FnMut(Self::Item) -> Option<B>,
        {
            self.find_map(f)
        }

        /// Calls `f` with `init` and each item in turn until it returns `None`
        fn try_for_each_with<T, F>(self, mut init: T, mut f: F) -> Option<()>
        where
            F: FnMut(&mut T, Self::Item) -> Option<()>,
        {
            for item in self {
                f(&mut init, item)?;
            }
            Some(())
        }
    }

    impl<I: Iterator> ParallelIterator for I {}
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    /// What the sequential stand-ins give for the calls the library makes.
    mod sequential {
        use crate::parallel::sequential::{
            IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
        };

        pub(super) fn flat_map_iter(items: &[u32]) -> Vec<u32> {
            items.par_iter().flat_map_iter(|&n| [n, n * 10]).collect()
        }

        pub(super) fn find_map_first(items: &[u32]) -> Option<(usize, u32)> {
            items
                .par_iter()
                .enumerate()
                .find_map_first(|(i, &n)| (n % 3 == 0).then_some((i, n)))
        }

        /// The items `try_for_each_with` was called with before an item over `limit`
        /// stopped it, and whether it ran to the end.
        // `&Vec`, not a slice: `Decoders::run` calls `into_par_iter` on a `&Vec`
        #[allow(clippy::ptr_arg)]
        pub(super) fn try_for_each_with(items: &Vec<u32>, limit: u32) -> (Vec<u32>, bool) {
            let (sender, receiver) = std::sync::mpsc::channel();
            let finished = items
                .into_par_iter()
                .try_for_each_with(sender, |s, &n| {
                    s.send(n).unwrap();
                    (n <= limit).then_some(())
                })
                .is_some();
            (receiver.try_iter().collect(), finished)
        }
    }

    /// The same calls with rayon.
    mod rayon {
        use rayon::prelude::*;

        pub(super) fn flat_map_iter(items: &[u32]) -> Vec<u32> {
            items.par_iter().flat_map_iter(|&n| [n, n * 10]).collect()
        }

        pub(super) fn find_map_first(items: &[u32]) -> Option<(usize, u32)> {
            items
                .par_iter()
                .enumerate()
                .find_map_first(|(i, &n)| (n % 3 == 0).then_some((i, n)))
        }
    }

    #[test]
    fn sequential_iterators_give_what_rayon_gives() {
        let items: Vec<u32> = (1..=200).collect();
        assert_eq!(
            sequential::flat_map_iter(&items),
            rayon::flat_map_iter(&items)
        );
        assert_eq!(sequential::flat_map_iter(&items)[..4], [1, 10, 2, 20]);
        // The first match in order, not just any match
        assert_eq!(sequential::find_map_first(&items), Some((2, 3)));
        assert_eq!(
            sequential::find_map_first(&items),
            rayon::find_map_first(&items)
        );
        assert_eq!(sequential::find_map_first(&[1, 2, 4]), None);
    }

    #[test]
    fn sequential_try_for_each_with_stops_at_the_first_none() {
        let items = vec![1, 2, 30, 4];
        assert_eq!(
            sequential::try_for_each_with(&items, 10),
            (vec![1, 2, 30], false)
        );
        assert_eq!(
            sequential::try_for_each_with(&items, 100),
            (vec![1, 2, 30, 4], true)
        );
    }
}
