//! An offset-keyed cache of already-parsed [HiveCell]s, avoiding re-reading and re-parsing the
//! same bytes from disk on repeated key/value lookups within a [crate::reader::HiveFiles].
//!
//! Entries inserted via [CellCache::insert_fixed] (the cells of the first hive bin, loaded
//! eagerly when a hive is opened — including the root cell) are marked [CachedCell::fixed] and
//! are never evicted by [CellCache::clean]. Entries inserted via [CellCache::insert] are subject
//! to eviction once the cache exceeds `max_entries`: [CellCache::clean] computes the median
//! "iterations since last read" and median read-count across all (non-fixed) entries, and evicts
//! any entry whose `last_read` is older than the median *unless* it was read more often than the
//! median and not read too long ago — an approximate LRU/LFU hybrid.

use std::{cell::RefCell, collections::BTreeMap};

use crate::cell::HiveCell;

pub struct CellCache {
    map: BTreeMap<u64, CachedCell>,
    iteration: RefCell<u64>,
    max_entries: usize,
}

#[derive(Debug)]
pub struct CachedCell {
    pub cell: HiveCell,
    pub readed: RefCell<u64>,
    pub last_read: RefCell<u64>,
    pub fixed: bool,
}

impl CachedCell {
    #[allow(unused)]
    pub fn new(cell: HiveCell) -> Self {
        Self {
            cell,
            readed: RefCell::new(0),
            last_read: RefCell::new(0),
            fixed: false,
        }
    }
    pub fn increase_counter(&self, iteration: u64) {
        let mut readed = match self.readed.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return,
        };
        *readed += 1;
        let mut last_read = match self.last_read.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return,
        };
        *last_read = iteration;
    }

    pub fn counters(&self) -> (u64, u64) {
        let readed = match self.readed.try_borrow() {
            Ok(v) => v,
            Err(_) => return (0, 0),
        };
        let last_read = match self.last_read.try_borrow() {
            Ok(v) => v,
            Err(_) => return (*readed, 0),
        };
        (*readed, *last_read)
    }
}

impl CellCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            iteration: RefCell::new(0),
            max_entries,
        }
    }
    fn increase_iteration(&self) -> u64 {
        let mut borrow = match self.iteration.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return u64::MAX,
        };
        *borrow += 1;
        *borrow
    }
    pub fn contains(&self, offset: u64) -> bool {
        self.increase_iteration();
        self.map.contains_key(&offset)
    }

    pub fn get(&self, offset: u64) -> Option<&HiveCell> {
        let iteration = self.increase_iteration();
        let cached = self.map.get(&offset)?;
        cached.increase_counter(iteration);
        Some(&cached.cell)
    }
    pub fn insert_fixed(&mut self, cell: HiveCell) {
        let iteration = self.increase_iteration();
        self.map.insert(
            cell.offset(),
            CachedCell {
                cell,
                last_read: RefCell::new(iteration),
                readed: RefCell::new(0),
                fixed: true,
            },
        );
    }

    pub fn insert(&mut self, cell: HiveCell) {
        let iteration = self.increase_iteration();
        if self.map.len() >= self.max_entries {
            self.clean();
        }
        self.map.insert(
            cell.offset(),
            CachedCell {
                cell,
                last_read: RefCell::new(iteration),
                readed: RefCell::new(0),
                fixed: false,
            },
        );
    }

    pub fn clean(&mut self) {
        if self.map.is_empty() {
            return;
        }
        let iteration = self.increase_iteration();
        let mut total_distance = 0;
        let mut readed_times = 0;
        self.map.iter().for_each(|(_, cached)| {
            let (readed, last_read) = cached.counters();
            total_distance += iteration - last_read;
            readed_times += readed;
        });
        let median = total_distance / self.map.len() as u64;
        let med_readed = readed_times / self.map.len() as u64;
        self.map.retain(|_, cached| {
            if cached.fixed {
                return true;
            }
            let (readed, last_read) = cached.counters();
            if last_read < median {
                if readed > med_readed && last_read > median / 2 {
                    return true;
                }
                return false;
            }
            true
        });
    }
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::cell::UnallocatedCell;

    fn cell_at(offset: u64) -> HiveCell {
        HiveCell::Unallocated(UnallocatedCell { offset })
    }

    #[test]
    fn fixed_entry_survives_repeated_clean_even_when_never_accessed() {
        let mut cache = CellCache::new(1);
        cache.insert_fixed(cell_at(100));
        for offset in 1..6 {
            // max_entries=1 makes every insert() trigger clean() first.
            cache.insert(cell_at(offset));
            assert!(
                cache.get(100).is_some(),
                "fixed entry was evicted after inserting offset {}",
                offset
            );
        }
    }

    #[test]
    fn frequently_accessed_entry_survives_while_untouched_entry_is_evicted() {
        let mut cache = CellCache::new(4);
        cache.insert(cell_at(1));
        cache.insert(cell_at(2));
        cache.insert(cell_at(3));
        cache.insert(cell_at(4));
        for _ in 0..5 {
            cache.get(1);
        }
        // Triggers clean(): entry 1 was just read repeatedly (small last_read distance from
        // "now"), while 2/3/4 were inserted once and never touched again (large distance).
        cache.insert(cell_at(5));
        assert!(cache.contains(1), "frequently-accessed entry was evicted");
        assert!(!cache.contains(2), "untouched entry 2 should have been evicted");
        assert!(!cache.contains(3), "untouched entry 3 should have been evicted");
        assert!(!cache.contains(4), "untouched entry 4 should have been evicted");
    }
}
