#![forbid(unsafe_code)]

use core::cmp::Ordering;

use crate::assert_h;
use crate::bzlib::{EState, BZ_N_OVERSHOOT};

/// Compare two cyclic rotations of `block` of length `n` using 64-bit word chunks.
#[inline]
fn compare_cyclic_suffixes(block: &[u8], n: usize, a: usize, b: usize, depth: usize) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let mut cur_a = a + depth;
    if cur_a >= n {
        cur_a -= n;
    }
    let mut cur_b = b + depth;
    if cur_b >= n {
        cur_b -= n;
    }
    let mut checked = depth;

    while checked + 8 <= n {
        let wa = u64::from_be_bytes(block[cur_a..cur_a + 8].try_into().unwrap());
        let wb = u64::from_be_bytes(block[cur_b..cur_b + 8].try_into().unwrap());
        if wa != wb {
            return wa.cmp(&wb);
        }
        checked += 8;
        cur_a += 8;
        if cur_a >= n {
            cur_a -= n;
        }
        cur_b += 8;
        if cur_b >= n {
            cur_b -= n;
        }
    }

    while checked < n {
        let ca = block[cur_a];
        let cb = block[cur_b];
        if ca != cb {
            return ca.cmp(&cb);
        }
        checked += 1;
        cur_a += 1;
        if cur_a == n {
            cur_a = 0;
        }
        cur_b += 1;
        if cur_b == n {
            cur_b = 0;
        }
    }

    Ordering::Equal
}

#[inline]
fn insertion_sort(s: &mut [u32], block: &[u8], nblock: usize, depth: usize) {
    for i in 1..s.len() {
        let val = s[i];
        let mut j = i;
        while j > 0
            && compare_cyclic_suffixes(block, nblock, val as usize, s[j - 1] as usize, depth)
                == Ordering::Less
        {
            s[j] = s[j - 1];
            j -= 1;
        }
        s[j] = val;
    }
}

#[inline(always)]
fn u16_at(block: &[u8], n: usize, pos: usize) -> u16 {
    let mut p = pos;
    if p >= n {
        p -= n;
    }
    u16::from_be_bytes([block[p], block[p + 1]])
}

#[inline(always)]
fn median_u16(a: u16, b: u16, c: u16) -> u16 {
    if a < b {
        if b < c {
            b
        } else if a < c {
            c
        } else {
            a
        }
    } else {
        if a < c {
            a
        } else if b < c {
            c
        } else {
            b
        }
    }
}

/// Multi-key ternary quicksort on B* suffixes using 16-bit words.
/// Advances depth by 2 bytes on equal partition without rescanning matched prefixes.
fn ssort_bstar(slice: &mut [u32], block: &[u8], nblock: usize, initial_depth: usize) {
    if slice.len() <= 1 {
        return;
    }
    if slice.len() <= 16 {
        insertion_sort(slice, block, nblock, initial_depth);
        return;
    }

    let mut stack = [(0usize, 0usize, 0usize); 256];
    let mut sp = 0;
    stack[sp] = (0, slice.len(), initial_depth);
    sp += 1;

    while sp > 0 {
        sp -= 1;
        let (offset, len, depth) = stack[sp];
        let s = &mut slice[offset..offset + len];

        if len <= 16 {
            insertion_sort(s, block, nblock, depth);
            continue;
        }

        if depth + 2 > nblock {
            insertion_sort(s, block, nblock, depth);
            continue;
        }

        let mid = len / 2;
        let w0 = u16_at(block, nblock, s[0] as usize + depth);
        let w1 = u16_at(block, nblock, s[mid] as usize + depth);
        let w2 = u16_at(block, nblock, s[len - 1] as usize + depth);
        let pivot = median_u16(w0, w1, w2);

        let mut lt = 0;
        let mut i = 0;
        let mut gt = len;
        while i < gt {
            let w = u16_at(block, nblock, s[i] as usize + depth);
            if w < pivot {
                if i != lt {
                    s.swap(i, lt);
                }
                lt += 1;
                i += 1;
            } else if w > pivot {
                gt -= 1;
                s.swap(i, gt);
            } else {
                i += 1;
            }
        }

        if lt == 0 && gt == len {
            if depth + 2 < nblock {
                stack[sp] = (offset, len, depth + 2);
                sp += 1;
            }
            continue;
        }

        let mut parts = [
            (offset, lt, depth),
            (offset + lt, gt - lt, depth + 2),
            (offset + gt, len - gt, depth),
        ];

        parts.sort_unstable_by_key(|p| core::cmp::Reverse(p.1));

        for &(p_off, p_len, p_depth) in &parts {
            if p_len > 1 && p_depth < nblock {
                if sp < 256 {
                    stack[sp] = (p_off, p_len, p_depth);
                    sp += 1;
                } else {
                    insertion_sort(&mut slice[p_off..p_off + p_len], block, nblock, p_depth);
                }
            }
        }
    }
}

/// Classify cyclic suffixes into S-type (1) and L-type (0).
/// Returns true if all characters in block are identical.
fn classify_cyclic_suffixes(block: &[u8], n: usize, is_s_type: &mut [u64]) -> bool {
    let words = n.div_ceil(64);
    is_s_type[..words].fill(0);

    let mut p = usize::MAX;
    for i in 0..n {
        let next_i = if i + 1 == n { 0 } else { i + 1 };
        if block[i] != block[next_i] {
            p = i;
            break;
        }
    }

    if p == usize::MAX {
        return true;
    }

    let next_p = if p + 1 == n { 0 } else { p + 1 };
    let mut curr_is_s = block[p] < block[next_p];
    if curr_is_s {
        is_s_type[p >> 6] |= 1 << (p & 63);
    }

    let mut i = if p == 0 { n - 1 } else { p - 1 };
    while i != p {
        let next_i = if i + 1 == n { 0 } else { i + 1 };
        let c = block[i];
        let next_c = block[next_i];
        if c < next_c {
            curr_is_s = true;
        } else if c > next_c {
            curr_is_s = false;
        }
        if curr_is_s {
            is_s_type[i >> 6] |= 1 << (i & 63);
        }
        i = if i == 0 { n - 1 } else { i - 1 };
    }

    false
}

#[inline(always)]
fn is_s(bitset: &[u64], i: usize) -> bool {
    ((bitset[i >> 6] >> (i & 63)) & 1) != 0
}

/// Main Two-Stage Induced Suffix Sorting (DivSufSort for BWT).
fn divsufsort_bwt(ptr: &mut [u32], block: &mut [u8], quadrant: &mut [u16], nblock: usize) -> i32 {
    if nblock == 0 {
        return 0;
    }
    if nblock == 1 {
        ptr[0] = 0;
        return 0;
    }

    // Overshoot padding copy
    for i in 0..BZ_N_OVERSHOOT {
        block[nblock + i] = block[i];
    }

    // Allocate bitset for S-type/L-type flags (112.5 KB on stack for max 900,000 block)
    let words_needed = nblock.div_ceil(64);
    let mut bitset = [0u64; 14063];
    let is_all_equal =
        classify_cyclic_suffixes(&block[..nblock], nblock, &mut bitset[..words_needed]);

    if is_all_equal {
        for (i, p) in ptr[..nblock].iter_mut().enumerate() {
            *p = i as u32;
        }
        return 0;
    }

    // Collect Type B* suffixes word-at-a-time using bitwise logic
    let mut num_bstar = 0;
    for word_idx in 0..words_needed {
        let w = bitset[word_idx];
        if w == 0 {
            continue;
        }
        let prev_w = if word_idx == 0 {
            let last_w = bitset[words_needed - 1];
            let last_bit = if nblock % 64 == 0 {
                last_w >> 63
            } else {
                (last_w >> ((nblock % 64) - 1)) & 1
            };
            (w << 1) | last_bit
        } else {
            (w << 1) | (bitset[word_idx - 1] >> 63)
        };
        let mut bstar_mask = w & !prev_w;
        while bstar_mask != 0 {
            let bit = bstar_mask.trailing_zeros() as usize;
            let i = (word_idx << 6) | bit;
            if i < nblock {
                ptr[num_bstar] = i as u32;
                num_bstar += 1;
            }
            bstar_mask &= bstar_mask - 1;
        }
    }

    if num_bstar > 0 {
        // 2-byte bucket sort for B* suffixes
        let mut bstar_ftab = [0u32; 65536];
        for &s in &ptr[..num_bstar] {
            let s_idx = s as usize;
            let c0 = block[s_idx] as usize;
            let s1 = if s_idx + 1 == nblock { 0 } else { s_idx + 1 };
            let c1 = block[s1] as usize;
            bstar_ftab[(c0 << 8) | c1] += 1;
        }

        let mut curr = 0u32;
        for count in bstar_ftab.iter_mut() {
            let tmp = *count;
            *count = curr;
            curr += tmp;
        }

        for &s in &ptr[..num_bstar] {
            let s_idx = s as usize;
            let c0 = block[s_idx] as usize;
            let s1 = if s_idx + 1 == nblock { 0 } else { s_idx + 1 };
            let c1 = block[s1] as usize;
            let bucket = (c0 << 8) | c1;
            let pos = bstar_ftab[bucket] as usize;
            bstar_ftab[bucket] += 1;
            quadrant[pos * 2] = (s & 0xFFFF) as u16;
            quadrant[pos * 2 + 1] = (s >> 16) as u16;
        }

        let mut start = 0;
        for &bstar_end in &bstar_ftab {
            let end = bstar_end as usize;
            if end > start {
                for i in start..end {
                    let low = quadrant[i * 2] as u32;
                    let high = quadrant[i * 2 + 1] as u32;
                    ptr[i] = low | (high << 16);
                }
                let count = end - start;
                if count == 2 {
                    let a = ptr[start] as usize;
                    let b = ptr[start + 1] as usize;
                    if compare_cyclic_suffixes(block, nblock, a, b, 2) == Ordering::Greater {
                        ptr.swap(start, start + 1);
                    }
                } else if count > 2 {
                    ssort_bstar(&mut ptr[start..end], block, nblock, 2);
                }
                start = end;
            }
        }
    }

    // Count 1-byte frequencies for bucket boundaries
    let mut count = [0usize; 256];
    for &b in &block[..nblock] {
        count[b as usize] += 1;
    }

    let mut bucket_start = [0usize; 256];
    let mut bucket_end = [0usize; 256];
    let mut total = 0;
    for c in 0..256 {
        bucket_start[c] = total;
        total += count[c];
        bucket_end[c] = total;
    }

    // Copy sorted B* suffixes into quadrant buffer before clearing ptr
    for i in 0..num_bstar {
        let val = ptr[i];
        quadrant[i * 2] = (val & 0xFFFF) as u16;
        quadrant[i * 2 + 1] = (val >> 16) as u16;
    }

    // Clear ptr to unassigned sentinel (u32::MAX)
    ptr.fill(u32::MAX);

    // Place sorted B* suffixes at bucket ends
    let mut tail = bucket_end;
    for i in (0..num_bstar).rev() {
        let low = quadrant[i * 2] as u32;
        let high = quadrant[i * 2 + 1] as u32;
        let s = low | (high << 16);
        let c = block[s as usize] as usize;
        tail[c] -= 1;
        ptr[tail[c]] = s;
    }

    // Phase 1: Induce L-type suffixes from left to right
    let mut head = bucket_start;
    for k in 0..nblock {
        let p = ptr[k];
        if p != u32::MAX {
            let j = if p == 0 { nblock - 1 } else { (p - 1) as usize };
            if !is_s(&bitset, j) {
                let c = block[j] as usize;
                ptr[head[c]] = j as u32;
                head[c] += 1;
            }
        }
    }

    // Phase 2: Induce S-type suffixes from right to left
    let mut tail = bucket_end;
    for k in (0..nblock).rev() {
        let p = ptr[k];
        if p != u32::MAX {
            let j = if p == 0 { nblock - 1 } else { (p - 1) as usize };
            if is_s(&bitset, j) {
                let c = block[j] as usize;
                tail[c] -= 1;
                ptr[tail[c]] = j as u32;
            }
        }
    }

    // Locate origPtr (index where ptr[k] == 0)
    let mut orig_ptr = -1;
    for (i, &p) in ptr[..nblock].iter().enumerate() {
        if p == 0 {
            orig_ptr = i as i32;
            break;
        }
    }

    orig_ptr
}

/// Main entry point called from `compress.rs`.
pub(crate) fn block_sort(s: &mut EState) {
    let nblock = usize::try_from(s.nblock).unwrap();
    if nblock == 0 {
        s.origPtr = 0;
        return;
    }

    let ptr = s.arr1.ptr();
    let (block, quadrant) = s.arr2.block_and_quadrant(nblock);

    s.origPtr = divsufsort_bwt(ptr, block, quadrant, nblock);

    assert_h!(s.origPtr != -1, 1003);
}
