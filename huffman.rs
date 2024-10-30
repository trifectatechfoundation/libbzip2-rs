use std::cmp;

use crate::bzlib::BZ2_bz__AssertH__fail;
pub type Bool = libc::c_uchar;

const BZ_MAX_ALPHA_SIZE: usize = 258;
const BZ_MAX_CODE_LEN: usize = 23;

#[inline]
fn weight_of(zz0: i32) -> i32 {
    zz0 & 0xffffff00u32 as i32
}

#[inline]
fn depth_of(zz1: i32) -> i32 {
    zz1 & 0xff
}

#[inline]
fn add_weights(zw1: i32, zw2: i32) -> i32 {
    (weight_of(zw1)).wrapping_add(weight_of(zw2)) | (1 + cmp::max(depth_of(zw1), depth_of(zw2)))
}

#[inline]
fn upheap(
    heap: &mut [i32; BZ_MAX_ALPHA_SIZE + 2],
    weight: &mut [i32; BZ_MAX_ALPHA_SIZE * 2],
    mut z: i32,
) {
    let tmp;
    tmp = heap[z as usize];
    while weight[tmp as usize] < weight[heap[(z >> 1) as usize] as usize] {
        heap[z as usize] = heap[(z >> 1) as usize];
        z >>= 1;
    }
    heap[z as usize] = tmp;
}

#[inline]
fn downheap(
    heap: &mut [i32; BZ_MAX_ALPHA_SIZE + 2],
    weight: &mut [i32; BZ_MAX_ALPHA_SIZE * 2],
    nHeap: i32,
    mut z: i32,
) {
    let mut yy: i32;
    let tmp: i32;
    tmp = heap[z as usize];
    loop {
        yy = z << 1;
        if yy > nHeap {
            break;
        }
        if yy < nHeap
            && weight[heap[(yy + 1) as usize] as usize] < weight[heap[yy as usize] as usize]
        {
            yy += 1;
        }
        if weight[tmp as usize] < weight[heap[yy as usize] as usize] {
            break;
        }
        heap[z as usize] = heap[yy as usize];
        z = yy;
    }
    heap[z as usize] = tmp;
}

pub unsafe fn BZ2_hbMakeCodeLengths(len: *mut u8, freq: *mut i32, alphaSize: i32, maxLen: i32) {
    let mut nNodes: i32;
    let mut nHeap: i32;
    let mut n1: i32;
    let mut n2: i32;
    let mut i: i32;
    let mut j: i32;
    let mut k: i32;
    let mut tooLong: bool;
    let mut heap = [0i32; BZ_MAX_ALPHA_SIZE + 2];
    let mut weight = [0i32; BZ_MAX_ALPHA_SIZE * 2];
    let mut parent = [0i32; BZ_MAX_ALPHA_SIZE * 2];
    i = 0;
    while i < alphaSize {
        weight[(i + 1) as usize] = (if *freq.offset(i as isize) == 0 as libc::c_int {
            1
        } else {
            *freq.offset(i as isize)
        }) << 8;
        i += 1;
    }
    loop {
        nNodes = alphaSize;
        nHeap = 0;
        heap[0] = 0;
        weight[0] = 0;
        parent[0] = -2;
        for i in 1..=alphaSize {
            parent[i as usize] = -1;
            nHeap += 1;
            heap[nHeap as usize] = i;
            upheap(&mut heap, &mut weight, nHeap);
        }
        if nHeap >= BZ_MAX_ALPHA_SIZE as libc::c_int + 2 {
            BZ2_bz__AssertH__fail(2001);
        }
        while nHeap > 1 {
            n1 = heap[1];
            heap[1] = heap[nHeap as usize];
            nHeap -= 1;
            downheap(&mut heap, &mut weight, nHeap, 1);
            n2 = heap[1];
            heap[1] = heap[nHeap as usize];
            nHeap -= 1;
            downheap(&mut heap, &mut weight, nHeap, 1);
            nNodes += 1;
            parent[n1 as usize] = nNodes;
            parent[n2 as usize] = nNodes;
            weight[nNodes as usize] = add_weights(weight[n1 as usize], weight[n2 as usize]);
            parent[nNodes as usize] = -1;
            nHeap += 1;
            heap[nHeap as usize] = nNodes;
            upheap(&mut heap, &mut weight, nHeap);
        }
        if nNodes >= BZ_MAX_ALPHA_SIZE as libc::c_int * 2 {
            BZ2_bz__AssertH__fail(2002);
        }
        tooLong = false;
        for i in 1..=alphaSize {
            j = 0;
            k = i;
            while parent[k as usize] >= 0 {
                k = parent[k as usize];
                j += 1;
            }
            *len.offset((i - 1) as isize) = j as u8;
            if j > maxLen {
                tooLong = true;
            }
        }
        if !tooLong {
            break;
        }
        for i in 1..=alphaSize {
            j = weight[i as usize] >> 8;
            j = 1 + j / 2;
            weight[i as usize] = j << 8;
        }
    }
}
pub unsafe fn BZ2_hbAssignCodes(
    code: *mut i32,
    length: *mut u8,
    minLen: i32,
    maxLen: i32,
    alphaSize: i32,
) {
    let mut n: i32;
    let mut vec: i32;
    let mut i: i32;
    vec = 0;
    n = minLen;
    while n <= maxLen {
        i = 0;
        while i < alphaSize {
            if *length.offset(i as isize) as libc::c_int == n {
                *code.offset(i as isize) = vec;
                vec += 1;
            }
            i += 1;
        }
        vec <<= 1;
        n += 1;
    }
}
pub unsafe fn BZ2_hbCreateDecodeTables(
    limit: *mut i32,
    base: *mut i32,
    perm: *mut i32,
    length: *mut u8,
    minLen: i32,
    maxLen: i32,
    alphaSize: i32,
) {
    let mut pp: i32;
    let mut i: i32;
    let mut j: i32;
    let mut vec: i32;
    pp = 0;
    i = minLen;
    while i <= maxLen {
        j = 0;
        while j < alphaSize {
            if *length.offset(j as isize) as libc::c_int == i {
                *perm.offset(pp as isize) = j;
                pp += 1;
            }
            j += 1;
        }
        i += 1;
    }
    i = 0;
    while i < BZ_MAX_CODE_LEN as libc::c_int {
        *base.offset(i as isize) = 0;
        i += 1;
    }
    i = 0;
    while i < alphaSize {
        let fresh0 = &mut (*base.offset((*length.offset(i as isize) + 1) as isize));
        *fresh0 += 1;
        i += 1;
    }
    i = 1;
    while i < BZ_MAX_CODE_LEN as libc::c_int {
        let fresh1 = &mut (*base.offset(i as isize));
        *fresh1 += *base.offset((i - 1) as isize);
        i += 1;
    }
    i = 0;
    while i < BZ_MAX_CODE_LEN as libc::c_int {
        *limit.offset(i as isize) = 0;
        i += 1;
    }
    vec = 0;
    i = minLen;
    while i <= maxLen {
        vec += *base.offset((i + 1) as isize) - *base.offset(i as isize);
        *limit.offset(i as isize) = vec - 1;
        vec <<= 1;
        i += 1;
    }
    i = minLen + 1;
    while i <= maxLen {
        *base.offset(i as isize) =
            ((*limit.offset((i - 1) as isize) + 1) << 1) - *base.offset(i as isize);
        i += 1;
    }
}
