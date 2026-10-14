use std::collections::BTreeMap;

/// Puts items that arrive out of order back in height order.
pub struct InOrder<T> {
    next: u32,
    waiting: BTreeMap<u32, T>,
}

impl<T> InOrder<T> {
    #[must_use]
    pub fn new(first: u32) -> Self {
        Self {
            next: first,
            waiting: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, height: u32, item: T) {
        self.waiting.insert(height, item);
    }

    /// The item for the next height, if it has arrived, without taking it.
    #[must_use]
    pub fn peek(&self) -> Option<&T> {
        self.waiting.get(&self.next)
    }

    /// The item for the next height, once it has arrived.
    pub fn pop(&mut self) -> Option<T> {
        let item = self.waiting.remove(&self.next)?;
        self.next += 1;
        Some(item)
    }

    #[must_use]
    pub fn next_height(&self) -> u32 {
        self.next
    }

    #[must_use]
    pub fn held(&self) -> usize {
        self.waiting.len()
    }
}

#[cfg(test)]
mod tests {
    use super::InOrder;

    #[test]
    fn items_come_out_in_height_order_whatever_order_they_arrive_in() {
        let mut order = InOrder::new(10);
        order.push(12, 'c');
        order.push(11, 'b');
        assert_eq!(order.pop(), None);
        order.push(10, 'a');
        assert_eq!(order.pop(), Some('a'));
        assert_eq!(order.pop(), Some('b'));
        assert_eq!(order.pop(), Some('c'));
        assert_eq!(order.pop(), None);
        assert_eq!(order.next_height(), 13);
        assert_eq!(order.held(), 0);
    }
}
