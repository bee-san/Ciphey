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

/// The sequential stand-ins for rayon's traits.
#[cfg(target_family = "wasm")]
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
