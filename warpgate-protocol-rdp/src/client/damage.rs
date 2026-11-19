//! Regions of the target's desktop that changed since the viewer was last sent them.
//!
//! The target-side client decodes every update into one framebuffer. Rather than queueing a
//! copy of each changed rectangle for the viewer — which, whenever the viewer's encoder or
//! link is slower than the target, piles up stale pixels and makes everything downstream
//! seconds behind — it records *where* the desktop changed, and sends the framebuffer's
//! current pixels for those regions once the viewer side has room for them. Updates the
//! viewer had no time for are folded into the next one instead of waiting in line.

use ironrdp_pdu::geometry::InclusiveRectangle;

/// Past this many separate regions, they are merged into their bounding box. Each region is
/// sent, diffed and encoded on its own, so a few rectangles are cheaper than one that spans
/// everything, but hundreds of tiny ones cost more in per-update overhead than they save.
const MAX_REGIONS: usize = 16;

#[derive(Debug, Default)]
pub(super) struct Damage {
    regions: Vec<InclusiveRectangle>,
}

impl Damage {
    pub(super) const fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.regions.clear();
    }

    /// Record that `region` changed. A region overlapping or touching one already recorded
    /// is merged with it, so no pixel is ever in two regions.
    pub(super) fn add(&mut self, region: &InclusiveRectangle) {
        if region.right < region.left || region.bottom < region.top {
            return;
        }
        let mut merged = region.clone();
        // A merged region can reach regions neither part reached, so merge until none does.
        while let Some(index) = self
            .regions
            .iter()
            .position(|other| touches(&merged, other))
        {
            let other = self.regions.swap_remove(index);
            merged = union(&merged, &other);
        }
        self.regions.push(merged);

        if self.regions.len() > MAX_REGIONS {
            let bounds = self.regions.drain(..).reduce(|a, b| union(&a, &b));
            self.regions.extend(bounds);
        }
    }

    /// Take one region to send.
    pub(super) fn pop(&mut self) -> Option<InclusiveRectangle> {
        self.regions.pop()
    }
}

/// Whether `a` and `b` overlap or share an edge.
fn touches(a: &InclusiveRectangle, b: &InclusiveRectangle) -> bool {
    // In u32: the edge's neighbour of a rectangle reaching 65535 is 65536.
    let reaches = |start: u16, end: u16| u32::from(start) <= u32::from(end) + 1;
    reaches(a.left, b.right)
        && reaches(b.left, a.right)
        && reaches(a.top, b.bottom)
        && reaches(b.top, a.bottom)
}

fn union(a: &InclusiveRectangle, b: &InclusiveRectangle) -> InclusiveRectangle {
    InclusiveRectangle {
        left: a.left.min(b.left),
        top: a.top.min(b.top),
        right: a.right.max(b.right),
        bottom: a.bottom.max(b.bottom),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: u16, top: u16, right: u16, bottom: u16) -> InclusiveRectangle {
        InclusiveRectangle {
            left,
            top,
            right,
            bottom,
        }
    }

    fn drain(damage: &mut Damage) -> Vec<InclusiveRectangle> {
        let mut regions: Vec<_> = std::iter::from_fn(|| damage.pop()).collect();
        regions.sort_by_key(|r| (r.top, r.left));
        regions
    }

    #[test]
    fn repeated_changes_to_one_place_are_sent_once() {
        let mut damage = Damage::default();
        for _ in 0..100 {
            damage.add(&rect(10, 10, 20, 20));
        }
        assert_eq!(drain(&mut damage), [rect(10, 10, 20, 20)]);
        assert!(damage.is_empty());
    }

    #[test]
    fn separate_changes_stay_separate() {
        let mut damage = Damage::default();
        damage.add(&rect(0, 0, 9, 9));
        damage.add(&rect(100, 100, 109, 109));
        assert_eq!(
            drain(&mut damage),
            [rect(0, 0, 9, 9), rect(100, 100, 109, 109)]
        );
    }

    #[test]
    fn overlapping_and_adjacent_changes_merge() {
        let mut damage = Damage::default();
        damage.add(&rect(0, 0, 9, 9));
        // Shares the edge at x = 10.
        damage.add(&rect(10, 0, 19, 9));
        // Overlaps the first.
        damage.add(&rect(5, 5, 14, 14));
        assert_eq!(drain(&mut damage), [rect(0, 0, 19, 14)]);
    }

    #[test]
    fn a_merge_that_reaches_further_regions_takes_them_in() {
        let mut damage = Damage::default();
        damage.add(&rect(0, 0, 9, 9));
        damage.add(&rect(30, 0, 39, 9));
        // Bridges the two.
        damage.add(&rect(5, 0, 34, 9));
        assert_eq!(drain(&mut damage), [rect(0, 0, 39, 9)]);
    }

    #[test]
    fn too_many_regions_become_their_bounding_box() {
        let mut damage = Damage::default();
        for i in 0..=MAX_REGIONS as u16 {
            damage.add(&rect(i * 20, i * 20, i * 20 + 9, i * 20 + 9));
        }
        let last = MAX_REGIONS as u16 * 20;
        assert_eq!(drain(&mut damage), [rect(0, 0, last + 9, last + 9)]);
    }

    #[test]
    fn every_changed_pixel_stays_covered() {
        let mut damage = Damage::default();
        let changes = [
            rect(0, 0, 0, 0),
            rect(500, 3, 640, 9),
            rect(2, 2, 3, 3),
            rect(65_530, 65_530, 65_535, 65_535),
            rect(600, 0, 700, 400),
        ];
        for change in &changes {
            damage.add(change);
        }
        let regions = drain(&mut damage);
        for change in &changes {
            assert!(
                regions.iter().any(|r| r.left <= change.left
                    && r.top <= change.top
                    && change.right <= r.right
                    && change.bottom <= r.bottom),
                "{change:?} is not covered by {regions:?}"
            );
        }
    }

    #[test]
    fn an_empty_or_inverted_region_is_ignored() {
        let mut damage = Damage::default();
        damage.add(&rect(10, 10, 9, 20));
        damage.add(&rect(10, 10, 20, 9));
        assert!(damage.is_empty());
    }

    #[test]
    fn clearing_forgets_everything() {
        let mut damage = Damage::default();
        damage.add(&rect(0, 0, 9, 9));
        damage.clear();
        assert!(damage.pop().is_none());
    }
}
