use crate::assert_h;
use crate::blocksort::BZ2_blockSort;
use crate::bzlib::{BZ2_bz__AssertH__fail, EState, BZ_MAX_SELECTORS, BZ_N_ITERS};
use crate::huffman::{BZ2_hbAssignCodes, BZ2_hbMakeCodeLengths};
pub unsafe fn BZ2_bsInitWrite(s: *mut EState) {
    (*s).bsLive = 0 as libc::c_int;
    (*s).bsBuff = 0 as libc::c_int as u32;
}
unsafe fn bsFinishWrite(s: *mut EState) {
    while (*s).bsLive > 0 as libc::c_int {
        *((*s).zbits).offset((*s).numZ as isize) = ((*s).bsBuff >> 24 as libc::c_int) as u8;
        (*s).numZ += 1;
        (*s).bsBuff <<= 8 as libc::c_int;
        (*s).bsLive -= 8 as libc::c_int;
    }
}
#[inline]
unsafe fn bsW(s: *mut EState, n: i32, v: u32) {
    while (*s).bsLive >= 8 as libc::c_int {
        *((*s).zbits).offset((*s).numZ as isize) = ((*s).bsBuff >> 24 as libc::c_int) as u8;
        (*s).numZ += 1;
        (*s).bsBuff <<= 8 as libc::c_int;
        (*s).bsLive -= 8 as libc::c_int;
    }
    (*s).bsBuff |= v << (32 as libc::c_int - (*s).bsLive - n);
    (*s).bsLive += n;
}
unsafe fn bsPutUInt32(s: *mut EState, u: u32) {
    bsW(
        s,
        8 as libc::c_int,
        ((u >> 24 as libc::c_int) as libc::c_long & 0xff as libc::c_long) as u32,
    );
    bsW(
        s,
        8 as libc::c_int,
        ((u >> 16 as libc::c_int) as libc::c_long & 0xff as libc::c_long) as u32,
    );
    bsW(
        s,
        8 as libc::c_int,
        ((u >> 8 as libc::c_int) as libc::c_long & 0xff as libc::c_long) as u32,
    );
    bsW(
        s,
        8 as libc::c_int,
        (u as libc::c_long & 0xff as libc::c_long) as u32,
    );
}
unsafe fn bsPutUChar(s: *mut EState, c: u8) {
    bsW(s, 8 as libc::c_int, c as u32);
}
unsafe fn makeMaps_e(s: *mut EState) {
    let mut i: i32;
    (*s).nInUse = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < 256 as libc::c_int {
        if (*s).inUse[i as usize] != 0 {
            (*s).unseqToSeq[i as usize] = (*s).nInUse as u8;
            (*s).nInUse += 1;
        }
        i += 1;
    }
}
unsafe fn generateMTFValues(s: *mut EState) {
    let mut yy: [u8; 256] = [0; 256];
    let mut i: i32;
    let mut j: i32;
    let mut zPend: i32;
    let mut wr: i32;
    let EOB: i32;
    let ptr: *mut u32 = (*s).ptr;
    let block: *mut u8 = (*s).block;
    let mtfv: *mut u16 = (*s).mtfv;
    makeMaps_e(s);
    EOB = (*s).nInUse + 1 as libc::c_int;
    i = 0 as libc::c_int;
    while i <= EOB {
        (*s).mtfFreq[i as usize] = 0 as libc::c_int;
        i += 1;
    }
    wr = 0 as libc::c_int;
    zPend = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < (*s).nInUse {
        yy[i as usize] = i as u8;
        i += 1;
    }
    i = 0 as libc::c_int;
    while i < (*s).nblock {
        let ll_i: u8;
        j = (*ptr.offset(i as isize)).wrapping_sub(1 as libc::c_int as libc::c_uint) as i32;
        if j < 0 as libc::c_int {
            j += (*s).nblock;
        }
        ll_i = (*s).unseqToSeq[*block.offset(j as isize) as usize];
        if yy[0 as libc::c_int as usize] == ll_i {
            zPend += 1;
        } else {
            if zPend > 0 as libc::c_int {
                zPend -= 1;
                loop {
                    if zPend & 1 as libc::c_int != 0 {
                        *mtfv.offset(wr as isize) = 1 as libc::c_int as u16;
                        wr += 1;
                        (*s).mtfFreq[1 as libc::c_int as usize] += 1;
                        (*s).mtfFreq[1 as libc::c_int as usize];
                    } else {
                        *mtfv.offset(wr as isize) = 0 as libc::c_int as u16;
                        wr += 1;
                        (*s).mtfFreq[0 as libc::c_int as usize] += 1;
                        (*s).mtfFreq[0 as libc::c_int as usize];
                    }
                    if zPend < 2 as libc::c_int {
                        break;
                    }
                    zPend = (zPend - 2 as libc::c_int) / 2 as libc::c_int;
                }
                zPend = 0 as libc::c_int;
            }
            let mut rtmp: u8;
            let mut ryy_j: *mut u8;
            let rll_i: u8;
            rtmp = yy[1 as libc::c_int as usize];
            yy[1 as libc::c_int as usize] = yy[0 as libc::c_int as usize];
            ryy_j = &mut *yy.as_mut_ptr().offset(1 as libc::c_int as isize) as *mut u8;
            rll_i = ll_i;
            while rll_i != rtmp {
                let rtmp2: u8;
                ryy_j = ryy_j.offset(1);
                rtmp2 = rtmp;
                rtmp = *ryy_j;
                *ryy_j = rtmp2;
            }
            yy[0 as libc::c_int as usize] = rtmp;
            j = ryy_j
                .offset_from(&mut *yy.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut u8)
                as libc::c_long as i32;
            *mtfv.offset(wr as isize) = (j + 1 as libc::c_int) as u16;
            wr += 1;
            (*s).mtfFreq[(j + 1 as libc::c_int) as usize] += 1;
            (*s).mtfFreq[(j + 1 as libc::c_int) as usize];
        }
        i += 1;
    }
    if zPend > 0 as libc::c_int {
        zPend -= 1;
        loop {
            if zPend & 1 as libc::c_int != 0 {
                *mtfv.offset(wr as isize) = 1 as libc::c_int as u16;
                wr += 1;
                (*s).mtfFreq[1 as libc::c_int as usize] += 1;
                (*s).mtfFreq[1 as libc::c_int as usize];
            } else {
                *mtfv.offset(wr as isize) = 0 as libc::c_int as u16;
                wr += 1;
                (*s).mtfFreq[0 as libc::c_int as usize] += 1;
                (*s).mtfFreq[0 as libc::c_int as usize];
            }
            if zPend < 2 as libc::c_int {
                break;
            }
            zPend = (zPend - 2 as libc::c_int) / 2 as libc::c_int;
        }
    }
    *mtfv.offset(wr as isize) = EOB as u16;
    wr += 1;
    (*s).mtfFreq[EOB as usize] += 1;
    (*s).mtfFreq[EOB as usize];
    (*s).nMTF = wr;
}
unsafe fn sendMTFValues(s: *mut EState) {
    const BZ_LESSER_ICOST: u8 = 0;
    const BZ_GREATER_ICOST: u8 = 15;

    let mut t: i32;
    let mut i: i32;
    let mut j: i32;
    let mut gs: i32;
    let mut ge: i32;
    let mut totc: i32;
    let mut bt: i32;
    let mut bc: i32;
    let mut nSelectors: usize = 0;
    let mut minLen: i32;
    let mut maxLen: i32;
    let mut selCtr: usize;
    let nGroups: i32;
    let mut nBytes: i32;

    /*--
    s.len: [[u8; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS];
    is a global because the decoder also needs it.

    s.code: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS];
    s.rfreq: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS];

    are also globals only used in this proc.
    Made global to keep stack frame size small.
    --*/

    let mut cost: [u16; 6] = [0; 6];
    let mut fave: [i32; 6] = [0; 6];

    let mtfv: *mut u16 = (*s).mtfv;

    if (*s).verbosity >= 3 {
        eprintln!(
            "      {} in block, {} after MTF & 1-2 coding, {}+2 syms in use",
            (*s).nblock,
            (*s).nMTF,
            (*s).nInUse,
        );
    }
    let alphaSize = usize::try_from((*s).nInUse + 2).unwrap_or(0);

    for t in (*s).len.iter_mut() {
        t[..alphaSize].fill(BZ_GREATER_ICOST);
    }

    /*--- Decide how many coding tables to use ---*/
    assert_h!((*s).nMTF > 0, 3001);
    if (*s).nMTF < 200 {
        nGroups = 2;
    } else if (*s).nMTF < 600 {
        nGroups = 3;
    } else if (*s).nMTF < 1200 {
        nGroups = 4;
    } else if (*s).nMTF < 2400 {
        nGroups = 5;
    } else {
        nGroups = 6;
    }

    /*--- Generate an initial set of coding tables ---*/
    {
        let mut tFreq: i32;
        let mut aFreq: i32;

        let mut nPart = nGroups;
        let mut remF = (*s).nMTF;
        let mut gs = 0i32;

        while nPart > 0 {
            tFreq = remF / nPart;
            ge = gs - 1;
            aFreq = 0;
            while aFreq < tFreq && ge < alphaSize as i32 - 1 {
                ge += 1;
                aFreq += (*s).mtfFreq[ge as usize];
            }
            if ge > gs && nPart != nGroups && nPart != 1 && (nGroups - nPart) % 2 == 1 {
                aFreq -= (*s).mtfFreq[ge as usize];
                ge -= 1;
            }

            if (*s).verbosity >= 3 {
                eprintln!(
                    "      initial group {}, [{} .. {}], has {} syms ({:4.1}%%)",
                    nPart,
                    gs,
                    ge,
                    aFreq,
                    100.0f64 * aFreq as f64 / (*s).nMTF as f64,
                );
            }

            for v in 0..alphaSize {
                if v as i32 >= gs && v as i32 <= ge {
                    (*s).len[(nPart - 1) as usize][v] = 0;
                } else {
                    (*s).len[(nPart - 1) as usize][v] = 15;
                }
            }
            nPart -= 1;
            gs = ge + 1;
            remF -= aFreq;
        }
    }

    /*---
       Iterate up to BZ_N_ITERS times to improve the tables.
    ---*/
    for iter in 0..BZ_N_ITERS {
        for t in 0..nGroups {
            fave[t as usize] = 0;
        }

        for t in 0..nGroups {
            for v in 0..alphaSize {
                (*s).rfreq[t as usize][v as usize] = 0 as libc::c_int;
            }
        }

        /*---
          Set up an auxiliary length table which is used to fast-track
          the common case (nGroups == 6).
        ---*/
        if nGroups == 6 {
            for v in 0..alphaSize {
                (*s).len_pack[v][0] = ((*s).len[1][v] as u32) << 16 | (*s).len[0][v] as u32;
                (*s).len_pack[v][1] = ((*s).len[3][v] as u32) << 16 | (*s).len[2][v] as u32;
                (*s).len_pack[v][2] = ((*s).len[5][v] as u32) << 16 | (*s).len[4][v] as u32;
            }
        }

        nSelectors = 0;
        totc = 0 as libc::c_int;
        gs = 0 as libc::c_int;
        loop {
            /*--- Set group start & end marks. --*/
            if gs >= (*s).nMTF {
                break;
            }
            ge = gs + 50 as libc::c_int - 1 as libc::c_int;
            if ge >= (*s).nMTF {
                ge = (*s).nMTF - 1 as libc::c_int;
            }

            /*--
               Calculate the cost of this group as coded
               by each of the coding tables.
            --*/
            for t in 0..nGroups {
                cost[t as usize] = 0;
            }

            if nGroups == 6 && 50 == ge - gs + 1 {
                let mut cost01: u32;
                let mut cost23: u32;
                let mut cost45: u32;
                let mut icv: u16;
                cost45 = 0 as libc::c_int as u32;
                cost23 = cost45;
                cost01 = cost23;

                macro_rules! BZ_ITER {
                    ($nn:expr) => {
                        icv = *mtfv.add((gs + $nn) as usize);
                        cost01 = cost01.wrapping_add((*s).len_pack[icv as usize][0]);
                        cost23 = cost23.wrapping_add((*s).len_pack[icv as usize][1]);
                        cost45 = cost45.wrapping_add((*s).len_pack[icv as usize][2]);
                    };
                }

                #[rustfmt::skip]
                let _ = {
                    BZ_ITER!(0);  BZ_ITER!(1);  BZ_ITER!(2);  BZ_ITER!(3);  BZ_ITER!(4);
                    BZ_ITER!(5);  BZ_ITER!(6);  BZ_ITER!(7);  BZ_ITER!(8);  BZ_ITER!(9);
                    BZ_ITER!(10); BZ_ITER!(11); BZ_ITER!(12); BZ_ITER!(13); BZ_ITER!(14);
                    BZ_ITER!(15); BZ_ITER!(16); BZ_ITER!(17); BZ_ITER!(18); BZ_ITER!(19);
                    BZ_ITER!(20); BZ_ITER!(21); BZ_ITER!(22); BZ_ITER!(23); BZ_ITER!(24);
                    BZ_ITER!(25); BZ_ITER!(26); BZ_ITER!(27); BZ_ITER!(28); BZ_ITER!(29);
                    BZ_ITER!(30); BZ_ITER!(31); BZ_ITER!(32); BZ_ITER!(33); BZ_ITER!(34);
                    BZ_ITER!(35); BZ_ITER!(36); BZ_ITER!(37); BZ_ITER!(38); BZ_ITER!(39);
                    BZ_ITER!(40); BZ_ITER!(41); BZ_ITER!(42); BZ_ITER!(43); BZ_ITER!(44);
                    BZ_ITER!(45); BZ_ITER!(46); BZ_ITER!(47); BZ_ITER!(48); BZ_ITER!(49);
                };

                cost[0] = (cost01 & 0xffff) as u16;
                cost[1] = (cost01 >> 16) as u16;
                cost[2] = (cost23 & 0xffff) as u16;
                cost[3] = (cost23 >> 16) as u16;
                cost[4] = (cost45 & 0xffff) as u16;
                cost[5] = (cost45 >> 16) as u16;
            } else {
                /*--- slow version which correctly handles all situations ---*/
                for i in gs..=ge {
                    let icv_0: u16 = *mtfv.offset(i as isize);

                    for t in 0..nGroups {
                        cost[t as usize] = (cost[t as usize] as libc::c_int
                            + (*s).len[t as usize][icv_0 as usize] as libc::c_int)
                            as u16;
                    }
                }
            }

            /*--
               Find the coding table which is best for this group,
               and record its identity in the selector table.
            --*/
            bc = 999999999;
            bt = -1;
            for t in 0..nGroups {
                if (cost[t as usize] as libc::c_int) < bc {
                    bc = cost[t as usize] as i32;
                    bt = t;
                }
            }
            totc += bc;
            fave[bt as usize] += 1;
            fave[bt as usize];
            (*s).selector[nSelectors] = bt as u8;
            nSelectors += 1;

            if nGroups == 6 && 50 == ge - gs + 1 {
                macro_rules! BZ_ITUR {
                    ($nn:expr) => {
                        (*s).rfreq[bt as usize][*mtfv.add((gs + $nn) as usize) as usize] += 1;
                    };
                }

                #[rustfmt::skip]
                let _ = {
                    BZ_ITUR!(0);  BZ_ITUR!(1);  BZ_ITUR!(2);  BZ_ITUR!(3);  BZ_ITUR!(4);
                    BZ_ITUR!(5);  BZ_ITUR!(6);  BZ_ITUR!(7);  BZ_ITUR!(8);  BZ_ITUR!(9);
                    BZ_ITUR!(10); BZ_ITUR!(11); BZ_ITUR!(12); BZ_ITUR!(13); BZ_ITUR!(14);
                    BZ_ITUR!(15); BZ_ITUR!(16); BZ_ITUR!(17); BZ_ITUR!(18); BZ_ITUR!(19);
                    BZ_ITUR!(20); BZ_ITUR!(21); BZ_ITUR!(22); BZ_ITUR!(23); BZ_ITUR!(24);
                    BZ_ITUR!(25); BZ_ITUR!(26); BZ_ITUR!(27); BZ_ITUR!(28); BZ_ITUR!(29);
                    BZ_ITUR!(30); BZ_ITUR!(31); BZ_ITUR!(32); BZ_ITUR!(33); BZ_ITUR!(34);
                    BZ_ITUR!(35); BZ_ITUR!(36); BZ_ITUR!(37); BZ_ITUR!(38); BZ_ITUR!(39);
                    BZ_ITUR!(40); BZ_ITUR!(41); BZ_ITUR!(42); BZ_ITUR!(43); BZ_ITUR!(44);
                    BZ_ITUR!(45); BZ_ITUR!(46); BZ_ITUR!(47); BZ_ITUR!(48); BZ_ITUR!(49);
                };
            } else {
                for i in gs..=ge {
                    (*s).rfreq[bt as usize][*mtfv.add(i as usize) as usize] += 1;
                    (*s).rfreq[bt as usize][*mtfv.add(i as usize) as usize];
                }
            }

            gs = ge + 1;
        }

        if (*s).verbosity >= 3 as libc::c_int {
            eprint!(
                "      pass {}: size is {}, grp uses are ",
                iter + 1,
                totc / 8,
            );
            for t in 0..nGroups {
                eprint!("{} ", fave[t as usize],);
            }
            eprintln!("");
        }

        /*--
          Recompute the tables based on the accumulated frequencies.
        --*/
        /* maxLen was changed from 20 to 17 in bzip2-1.0.3.  See
        comment in huffman.c for details. */
        for t in 0..nGroups {
            BZ2_hbMakeCodeLengths(
                &mut *(*((*s).len).as_mut_ptr().offset(t as isize))
                    .as_mut_ptr()
                    .offset(0 as libc::c_int as isize),
                &mut *(*((*s).rfreq).as_mut_ptr().offset(t as isize))
                    .as_mut_ptr()
                    .offset(0 as libc::c_int as isize),
                alphaSize as i32,
                17 as libc::c_int,
            );
        }
    }

    assert_h!(nGroups < 8, 3002);
    assert_h!(nSelectors < 32768 && nSelectors <= BZ_MAX_SELECTORS, 3003);

    let mut pos: [u8; 6] = [0; 6];
    let mut ll_i: u8;
    let mut tmp2: u8;
    let mut tmp: u8;
    i = 0 as libc::c_int;
    while i < nGroups {
        pos[i as usize] = i as u8;
        i += 1;
    }
    for i in 0..nSelectors {
        ll_i = (*s).selector[i as usize];
        j = 0 as libc::c_int;
        tmp = pos[j as usize];
        while ll_i != tmp {
            j += 1;
            tmp2 = tmp;
            tmp = pos[j as usize];
            pos[j as usize] = tmp2;
        }
        pos[0 as libc::c_int as usize] = tmp;
        (*s).selectorMtf[i as usize] = j as u8;
    }
    t = 0 as libc::c_int;
    while t < nGroups {
        minLen = 32 as libc::c_int;
        maxLen = 0 as libc::c_int;
        for i in 0..alphaSize {
            if (*s).len[t as usize][i] as libc::c_int > maxLen {
                maxLen = (*s).len[t as usize][i] as i32;
            }
            if ((*s).len[t as usize][i] as libc::c_int) < minLen {
                minLen = (*s).len[t as usize][i] as i32;
            }
        }
        if maxLen > 17 as libc::c_int {
            BZ2_bz__AssertH__fail(3004 as libc::c_int);
        }
        if minLen < 1 as libc::c_int {
            BZ2_bz__AssertH__fail(3005 as libc::c_int);
        }
        BZ2_hbAssignCodes(
            &mut *(*((*s).code).as_mut_ptr().offset(t as isize))
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize),
            &mut *(*((*s).len).as_mut_ptr().offset(t as isize))
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize),
            minLen,
            maxLen,
            alphaSize as i32,
        );
        t += 1;
    }

    /*--- Transmit the mapping table. ---*/
    {
        let inUse16: [bool; 16] =
            core::array::from_fn(|i| (*s).inUse[i * 16..][..16].iter().any(|x| *x != 0));

        nBytes = (*s).numZ;
        for in_use in inUse16 {
            bsW(s, 1, in_use as u32);
        }
        for (any_in_use, chunk_in_use) in inUse16.iter().zip((*s).inUse.chunks_exact(16)) {
            if *any_in_use {
                for in_use in chunk_in_use {
                    bsW(s, 1, *in_use as u32);
                }
            }
        }
        if (*s).verbosity >= 3 {
            eprint!("      bytes: mapping {}, ", (*s).numZ - nBytes,);
        }
    }

    /*--- Now the selectors. ---*/
    nBytes = (*s).numZ;
    bsW(s, 3, nGroups as u32);
    bsW(s, 15, nSelectors as u32);

    for i in 0..nSelectors {
        for _ in 0..(*s).selectorMtf[i as usize] {
            bsW(s, 1, 1);
        }
        bsW(s, 1, 0);
    }
    if (*s).verbosity >= 3 {
        eprint!("selectors {}, ", (*s).numZ - nBytes);
    }

    /*--- Now the coding tables. ---*/
    nBytes = (*s).numZ;

    for t in 0..nGroups {
        let mut curr = (*s).len[t as usize][0];
        bsW(s, 5 as libc::c_int, curr as u32);
        for i in 0..alphaSize {
            while curr < (*s).len[t as usize][i as usize] {
                bsW(s, 2, 2);
                curr += 1;
            }
            while curr > (*s).len[t as usize][i as usize] {
                bsW(s, 2, 3);
                curr -= 1;
            }
            bsW(s, 1, 0);
        }
    }
    if (*s).verbosity >= 3 {
        eprint!("code lengths {}, ", (*s).numZ - nBytes);
    }

    /*--- And finally, the block data proper ---*/
    nBytes = (*s).numZ;
    selCtr = 0;
    gs = 0;
    loop {
        if gs >= (*s).nMTF {
            break;
        }
        ge = gs + 50 as libc::c_int - 1 as libc::c_int;
        if ge >= (*s).nMTF {
            ge = (*s).nMTF - 1 as libc::c_int;
        }
        assert_h!(((*s).selector[selCtr] as libc::c_int) < nGroups, 3006);
        if nGroups == 6 && 50 == ge - gs + 1 {
            /*--- fast track the common case ---*/
            let mut mtfv_i: u16;
            let s_len_sel_selCtr = &(*s).len[(*s).selector[selCtr] as usize];
            let s_code_sel_selCtr = &(*s).code[(*s).selector[selCtr] as usize];

            macro_rules! BZ_ITAH {
                ($nn:expr) => {
                    mtfv_i = *mtfv.add((gs + $nn) as usize);
                    bsW(
                        s,
                        s_len_sel_selCtr[mtfv_i as usize] as i32,
                        s_code_sel_selCtr[mtfv_i as usize] as u32,
                    );
                };
            }

            #[rustfmt::skip]
            let _ = {
                BZ_ITAH!(0);  BZ_ITAH!(1);  BZ_ITAH!(2);  BZ_ITAH!(3);  BZ_ITAH!(4);
                BZ_ITAH!(5);  BZ_ITAH!(6);  BZ_ITAH!(7);  BZ_ITAH!(8);  BZ_ITAH!(9);
                BZ_ITAH!(10); BZ_ITAH!(11); BZ_ITAH!(12); BZ_ITAH!(13); BZ_ITAH!(14);
                BZ_ITAH!(15); BZ_ITAH!(16); BZ_ITAH!(17); BZ_ITAH!(18); BZ_ITAH!(19);
                BZ_ITAH!(20); BZ_ITAH!(21); BZ_ITAH!(22); BZ_ITAH!(23); BZ_ITAH!(24);
                BZ_ITAH!(25); BZ_ITAH!(26); BZ_ITAH!(27); BZ_ITAH!(28); BZ_ITAH!(29);
                BZ_ITAH!(30); BZ_ITAH!(31); BZ_ITAH!(32); BZ_ITAH!(33); BZ_ITAH!(34);
                BZ_ITAH!(35); BZ_ITAH!(36); BZ_ITAH!(37); BZ_ITAH!(38); BZ_ITAH!(39);
                BZ_ITAH!(40); BZ_ITAH!(41); BZ_ITAH!(42); BZ_ITAH!(43); BZ_ITAH!(44);
                BZ_ITAH!(45); BZ_ITAH!(46); BZ_ITAH!(47); BZ_ITAH!(48); BZ_ITAH!(49);
            };
        } else {
            /*--- slow version which correctly handles all situations ---*/
            for i in gs..=ge {
                bsW(
                    s,
                    (*s).len[(*s).selector[selCtr] as usize][*mtfv.offset(i as isize) as usize]
                        as i32,
                    (*s).code[(*s).selector[selCtr] as usize][*mtfv.offset(i as isize) as usize]
                        as u32,
                );
            }
        }
        gs = ge + 1;
        selCtr += 1;
    }
    assert_h!(selCtr == nSelectors, 3007);

    if (*s).verbosity >= 3 {
        eprintln!("codes {}", (*s).numZ - nBytes);
    }
}
pub unsafe fn BZ2_compressBlock(s: *mut EState, is_last_block: bool) {
    if (*s).nblock > 0 as libc::c_int {
        (*s).blockCRC = !(*s).blockCRC;
        (*s).combinedCRC =
            (*s).combinedCRC << 1 as libc::c_int | (*s).combinedCRC >> 31 as libc::c_int;
        (*s).combinedCRC ^= (*s).blockCRC;
        if (*s).blockNo > 1 as libc::c_int {
            (*s).numZ = 0 as libc::c_int;
        }
        if (*s).verbosity >= 2 as libc::c_int {
            eprintln!(
                "   block {}: crc = 0x{:08x}, combined CRC = 0x{:08x}, size = {}",
                (*s).blockNo,
                (*s).blockCRC,
                (*s).combinedCRC,
                (*s).nblock,
            );
        }
        BZ2_blockSort(&mut *s);
    }
    (*s).zbits = &mut *((*s).arr2 as *mut u8).offset((*s).nblock as isize) as *mut u8;
    if (*s).blockNo == 1 as libc::c_int {
        BZ2_bsInitWrite(s);
        bsPutUChar(s, 0x42 as libc::c_int as u8);
        bsPutUChar(s, 0x5a as libc::c_int as u8);
        bsPutUChar(s, 0x68 as libc::c_int as u8);
        bsPutUChar(s, (0x30 as libc::c_int + (*s).blockSize100k) as u8);
    }
    if (*s).nblock > 0 as libc::c_int {
        bsPutUChar(s, 0x31 as libc::c_int as u8);
        bsPutUChar(s, 0x41 as libc::c_int as u8);
        bsPutUChar(s, 0x59 as libc::c_int as u8);
        bsPutUChar(s, 0x26 as libc::c_int as u8);
        bsPutUChar(s, 0x53 as libc::c_int as u8);
        bsPutUChar(s, 0x59 as libc::c_int as u8);
        bsPutUInt32(s, (*s).blockCRC);
        bsW(s, 1 as libc::c_int, 0 as libc::c_int as u32);
        bsW(s, 24 as libc::c_int, (*s).origPtr as u32);
        generateMTFValues(s);
        sendMTFValues(s);
    }
    if is_last_block {
        bsPutUChar(s, 0x17 as libc::c_int as u8);
        bsPutUChar(s, 0x72 as libc::c_int as u8);
        bsPutUChar(s, 0x45 as libc::c_int as u8);
        bsPutUChar(s, 0x38 as libc::c_int as u8);
        bsPutUChar(s, 0x50 as libc::c_int as u8);
        bsPutUChar(s, 0x90 as libc::c_int as u8);
        bsPutUInt32(s, (*s).combinedCRC);
        if (*s).verbosity >= 2 as libc::c_int {
            eprint!("    final combined CRC = 0x{:08x}\n   ", (*s).combinedCRC);
        }
        bsFinishWrite(s);
    }
}
