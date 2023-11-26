use std::{collections::BTreeMap, cell::RefCell};

use crate::cell::HiveCell;

pub struct CellCache {
    map : BTreeMap<u64, CachedCell>,
    iteration : RefCell<u64>,
    max_entries : usize
}

#[derive(Debug)]
pub struct CachedCell {
    pub cell : HiveCell,
    pub readed : RefCell<u64>,
    pub last_read : RefCell<u64>,
    pub fixed : bool
}

impl CachedCell {
    #[allow(unused)]
    pub fn new(cell : HiveCell) -> Self {
        Self {
            cell,
            readed : RefCell::new(0),
            last_read : RefCell::new(0),
            fixed : false
        }
    }
    pub fn increase_counter(&self, iteration : u64) {
        let mut readed = match self.readed.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return
        };
        *readed += 1;
        let mut last_read = match self.last_read.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return
        };
        *last_read = iteration;
    }

    pub fn counters(&self) -> (u64, u64) {
        let readed = match self.readed.try_borrow() {
            Ok(v) => v,
            Err(_) => return (0,0)
        };
        let last_read = match self.last_read.try_borrow() {
            Ok(v) => v,
            Err(_) => return (*readed, 0)
        };
        (*readed, *last_read)
    }
}

impl CellCache {
    pub fn new(max_entries : usize) -> Self {
        Self {
            map : BTreeMap::new(),
            iteration : RefCell::new(0),
            max_entries
        }
    }
    fn increase_iteration(&self) -> u64 {
        let mut borrow = match self.iteration.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return u64::MAX
        };
        *borrow += 1;
        *borrow
    }
    pub fn contains(&self, offset : u64) -> bool {
        self.increase_iteration();
        self.map.contains_key(&offset)
    }

    pub fn get(&self, offset : u64) -> Option<&HiveCell> {
        let iteration = self.increase_iteration();
        let cached = self.map.get(&offset)?;
        cached.increase_counter(iteration);
        Some(&cached.cell)
    }
    pub fn insert_fixed(&mut self, cell : HiveCell) {
        let iteration = self.increase_iteration();
        self.map.insert(cell.offset(), CachedCell {
            cell,
            last_read : RefCell::new(iteration),
            readed : RefCell::new(0),
            fixed : true
        });
    }

    pub fn insert(&mut self, cell : HiveCell) {
        let iteration = self.increase_iteration();
        if self.map.len() >= self.max_entries {
            self.clean();
        }
        self.map.insert(cell.offset(), CachedCell {
            cell,
            last_read : RefCell::new(iteration),
            readed : RefCell::new(0),
            fixed : false
        });
    }

    pub fn clean(&mut self) {
        let iteration = self.increase_iteration();
        let mut total_distance = 0;
        let mut readed_times = 0;
        self.map.iter().for_each(|(_,cached)| {
            let (readed, last_read) = cached.counters();
            total_distance += iteration - last_read;
            readed_times += readed;
        });
        let median = total_distance / self.map.len() as u64;
        let med_readed = readed_times / self.map.len() as u64;
        self.map.retain(|_,cached| {
            let (readed, last_read) = cached.counters();
            if last_read < median {
                if readed > med_readed && last_read > median / 2 {
                    return true;
                }
                return false
            }
            true
        });
    }
}