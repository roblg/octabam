| 4-VOICE KIT -- a FLEX track whose sample is named KIT4* plays four sample
| voices, one per slice of that sample, each striking and ringing on its own.
| GNU as, -mcpu=5475. A DRAM unit (Linked(dram=True)).
|
| THE MACHINE. The sample's first four slices are the kit's four voices
| (slices 1..4 as the audio editor numbers them); a sample with no slices is
| cut into four equal quarters of its trim, so four hits of one length
| concatenated need no .ot. At every trig (a voice start on the track) STRT
| picks which voices strike, as a 4-bit mask:
|     STRT 1 = V1, 2 = V2, 4 = V3, 8 = V4, sums for several (3 = V1+V2,
|     15 = all four); 0 (a fresh Part) = V1; only the low four bits count.
| A struck voice restarts at its slice's start; the others keep ringing, so
| a hat over a kick does not cut the kick. Each voice plays its slice to
| the end at unity and the four are summed, saturating. Everything after
| the source is the track's own: PTCH and RATE tune the whole kit (the DSP
| resamples the mix), the AMP envelope, filter, FX1/FX2, level and pan
| shape the mix -- set AMP ATK 0 / HOLD INF so a trig's envelope does not
| cut the voices still ringing. A stock unit plays KIT4*.wav as a sample.
|
| HOW (the SYNTH machine's method, timhastie/octatrick-modules synth.s):
| the per-frame record packer renders each track through the kind table
| 0x400d6434; the FLEX entry 0x400d6438 (stock 0x40004008) points here.
| kv_render has the stock renderer's signature -- (track, ping, start, end),
| C convention, the record cursor at 0x80001c80 -- calls the stock
| renderer, which keeps the voice lifecycle, the rate and the records'
| headers, then overwrites every source pair it shipped with the kit's
| mix. A record is a 16-byte header (+3 = the source pair count) then that
| many pairs of 8 bytes (L long, R long; the DSP takes the top 24 bits);
| the call's records run from the cursor it started at to the cursor it
| left, walked header by header.
|
| THE SOURCE. The voices read the sample through the stock FLEX fetch
| 0x40095bdc (fetch(voice, position) -> d0 = the frames' address in the
| audio page arena, d1 = frames contiguous there), handed a per-track
| SHADOW voice: the playing voice's slot (+21) and format (+30), loop off
| (+23), forward (+36), and a region (+40..+63) that is the struck slice.
| So the page arithmetic, and the arena base the DRAM platform moves, stay
| the stock routine's. Formats (+30, the stock copy loop 0x4000874e): 0 =
| 24-bit mono, 1 = 24-bit stereo, 2 = 16-bit mono, 3 = 16-bit stereo.
|
| The settings record (0x100b14f0 + 0x448 * slot, the voice's +8): the path
| string at +0, the trim at +300 (start, end, loop: 12 bytes), slice k at
| +312 + 12k (start, end, loop), the slice count at +1092 (the voice start
| 0x4000f6b8..0x4000f6da reads them so).
|
| The marker is resolved on the frame's second call when bit 4 of the
| per-track event byte 0x46104d0c + track says a voice starts this frame;
| the start handler has run by then (voice +8, +21, +30 are the new
| voice's). The first call of that frame renders the old voices' tail, the
| second the struck voices from the trig's sub-frame position on.
|
| Position independent: OS absolutes and pc-relative references only.

        .text
        .set    VOICE_BASE, 0x800049d8
        .set    VOICE_STRIDE, 0xa8
        .set    CURSOR, 0x80001c80
        .set    NIBBLE, 0x46104d0c
        .set    STOCK_RENDER, 0x40004008
        .set    FLEX_FETCH, 0x40095bdc
        .set    FP_PTR, 0x800062a8       | the packer's per-track DSP parameter record (STRT at +2)
        .set    SETTINGS_BASE, 0x100b14f0
        .set    SETTINGS_SPAN, 0x24640   | 136 * 0x448
        .set    SET_TRIM, 300
        .set    SET_SLICE, 312
        .set    SET_COUNT, 1092
        .set    MAX_RECORDS, 8           | a runaway walk stops here

        .set    T_STRIDE, 128            | per-track state
        .set    T_ON, 0                  | byte: the playing voice is a kit
        .set    T_V, 8                   | 4 voices x 8: position, end (position >= end = silent)
        .set    T_SH, 64                 | the shadow voice (fields +21 .. +63 used)
        .set    SH_SLOT, 21
        .set    SH_LOOP, 23
        .set    SH_FMT, 30
        .set    SH_DIR, 36
        .set    SH_REGION, 40

| ---- kv_render(track, ping, start, end) ------------------------------------
        .globl  kv_render
kv_render:
        lea     -48(%sp),%sp
        movem.l %d2-%d7/%a2-%a6,(%sp)    | 44(sp) the return value; args 52 track, 56 ping, 60 start, 64 end
        move.l  CURSOR,%a2               | the first record this call writes
        move.l  52(%sp),%d2              | track
        move.l  %d2,%d3
        lsl.l   #7,%d3                   | * T_STRIDE
        lea     kv_state(%pc),%a3
        add.l   %d3,%a3                  | a3 = this track's state
        moveq   #16,%d1
        cmp.l   64(%sp),%d1              | the frame's second call?
        bne     kv_call
        lea     NIBBLE,%a0
        lea     (%a0,%d2.l),%a0
        btst    #4,(%a0)                 | a voice starts this frame
        beq     kv_call
        bsr     kv_start
kv_call:
        move.l  64(%sp),-(%sp)           | end
        move.l  64(%sp),-(%sp)           | start
        move.l  64(%sp),-(%sp)           | ping
        move.l  64(%sp),-(%sp)           | track
        jsr     STOCK_RENDER
        lea     16(%sp),%sp
        move.l  %d0,44(%sp)
        tst.b   T_ON(%a3)
        beq     kv_done
        move.l  CURSOR,%a6               | where the call's records end
        moveq   #MAX_RECORDS,%d7
kv_rec:
        cmpa.l  %a6,%a2
        bcc     kv_done
        mvz.b   3(%a2),%d6               | source pairs in this record
        lea     16(%a2),%a4              | the first pair
        move.l  %d6,%d0
        lsl.l   #3,%d0
        lea     (%a4,%d0.l),%a5          | the next record
        tst.l   %d6
        beq     kv_next
        bsr     kv_fill
kv_next:
        move.l  %a5,%a2
        subq.l  #1,%d7
        bne     kv_rec
kv_done:
        move.l  44(%sp),%d0
        movem.l (%sp),%d2-%d7/%a2-%a6
        lea     48(%sp),%sp
        rts

| ---- kv_start: resolve the marker; strike the voices STRT selects ---------
| d2 = track, a3 = its state. Clobbers d0, d1, d3-d6, a0, a1, a4.
kv_start:
        move.l  #VOICE_STRIDE,%d3
        muls.l  %d2,%d3
        lea     VOICE_BASE,%a4
        add.l   %d3,%a4                  | a4 = the voice
        move.l  8(%a4),%a0               | its settings record
        move.l  %a0,%d3
        subi.l  #SETTINGS_BASE,%d3       | only a pointer INTO the settings table is read
        cmpi.l  #SETTINGS_SPAN,%d3       | (after power-on RAM holds garbage; synth.s)
        bhs     kv_off
        move.l  %a0,%a1                  | a1 = start of the file name
        move.l  #255,%d3
kv_scan:
        mvz.b   (%a0)+,%d1
        beq     kv_scanned
        cmpi.l  #'/',%d1
        bne     kv_scan1
        move.l  %a0,%a1                  | after the last '/'
kv_scan1:
        subq.l  #1,%d3
        bne     kv_scan
kv_scanned:
        lea     kv_name(%pc),%a0
        moveq   #4,%d3
kv_cmp:
        mvz.b   (%a0)+,%d1
        mvz.b   (%a1)+,%d5
        cmp.l   %d5,%d1
        bne     kv_off
        subq.l  #1,%d3
        bne     kv_cmp
        tst.b   T_ON(%a3)                | a track that was not a kit: every voice silent
        bne     kv_on
        moveq   #0,%d0
        moveq   #7,%d1
        lea     T_V(%a3),%a0
kv_clr:
        move.l  %d0,(%a0)+
        subq.l  #1,%d1
        bpl     kv_clr
kv_on:
        move.b  #1,T_ON(%a3)
        lea     T_SH(%a3),%a1            | the shadow voice
        move.b  21(%a4),SH_SLOT(%a1)
        clr.b   SH_LOOP(%a1)
        move.b  30(%a4),SH_FMT(%a1)
        move.w  #1,SH_DIR(%a1)
        move.l  8(%a4),%a4               | a4 = the settings record
        move.l  FP_PTR,%a0
        mvz.b   2(%a0),%d6               | STRT raw
        moveq   #15,%d0
        and.l   %d0,%d6                  | the mask
        bne     kv_mask
        moveq   #1,%d6                   | 0 = V1
kv_mask:
        move.l  SET_COUNT(%a4),%d5       | slices
        moveq   #0,%d4                   | v
        lea     T_V(%a3),%a1
kv_strike:
        btst    %d4,%d6
        beq     kv_snext
        cmp.l   %d4,%d5
        bgt     kv_slice                 | count > v: slice v
        tst.l   %d5
        bne     kv_snext                 | fewer slices than voices: this one has none
        move.l  SET_TRIM+4(%a4),%d0      | no slices: quarter v of the trim
        move.l  SET_TRIM(%a4),%d1
        sub.l   %d1,%d0
        asr.l   #2,%d0                   | the quarter's length
        move.l  %d0,%d3
        muls.l  %d4,%d3
        add.l   %d3,%d1
        move.l  %d1,(%a1)                | position
        add.l   %d0,%d1
        move.l  %d1,4(%a1)               | end
        bra     kv_snext
kv_slice:
        move.l  %d4,%d0
        lsl.l   #2,%d0
        move.l  %d0,%d1
        add.l   %d0,%d0
        add.l   %d1,%d0                  | v * 12
        lea     (%a4,%d0.l),%a0
        lea     SET_SLICE(%a0),%a0
        move.l  (%a0)+,(%a1)             | position = the slice's start
        move.l  (%a0),4(%a1)             | end
kv_snext:
        addq.l  #8,%a1
        addq.l  #1,%d4
        moveq   #4,%d0
        cmp.l   %d0,%d4
        blt     kv_strike
        rts
kv_off:
        clr.b   T_ON(%a3)
        rts

| ---- kv_fill: the kit's mix into d6 pairs at a4 ---------------------------
| a3 = the track's state. Keeps a2, a3, a5, a6, d7; clobbers the rest.
kv_fill:
        move.l  %a4,%a0                  | clear: the voices add into the pairs
        move.l  %d6,%d0
        moveq   #0,%d1
kv_zero:
        move.l  %d1,(%a0)+
        move.l  %d1,(%a0)+
        subq.l  #1,%d0
        bne     kv_zero
        moveq   #0,%d4                   | v * 8
kv_voice:
        lea     T_V(%a3,%d4.l),%a1
        move.l  (%a1),%d2                | position
        cmp.l   4(%a1),%d2
        bge     kv_vnext                 | silent
        lea     -8(%sp),%sp
        movem.l %d4/%a4,(%sp)
        move.l  %d6,%d5                  | pairs left
kv_chunk:
        lea     T_SH(%a3),%a1
        lea     T_V(%a3,%d4.l),%a0
        move.l  4(%a0),%d0               | the region: [0, end) three times over
        moveq   #0,%d1
        move.l  %d1,SH_REGION(%a1)
        move.l  %d0,SH_REGION+4(%a1)
        move.l  %d1,SH_REGION+8(%a1)
        move.l  %d0,SH_REGION+12(%a1)
        move.l  %d1,SH_REGION+16(%a1)
        move.l  %d0,SH_REGION+20(%a1)
        move.l  %d2,-(%sp)               | position
        move.l  %a1,-(%sp)               | the shadow voice
        jsr     FLEX_FETCH
        addq.l  #8,%sp
        tst.l   %d1
        ble     kv_end                   | nothing left: the voice ends
        cmp.l   %d5,%d1
        ble     kv_n
        move.l  %d5,%d1
kv_n:
        move.l  %d0,%a0                  | the frames
        add.l   %d1,%d2                  | position += n
        sub.l   %d1,%d5
        move.l  %d1,%d3                  | n
        lea     T_SH(%a3),%a1
        mvz.b   SH_FMT(%a1),%d0
        subq.l  #1,%d0
        blt     kv_m24
        beq     kv_s24
        subq.l  #1,%d0
        beq     kv_m16
kv_s16:                                  | 3: 16-bit stereo
        mvs.w   (%a0)+,%d0
        moveq   #14,%d1
        asl.l   %d1,%d0                  | s16 << 16 >> 2
        add.l   %d0,(%a4)+
        mvs.w   (%a0)+,%d0
        asl.l   %d1,%d0
        add.l   %d0,(%a4)+
        subq.l  #1,%d3
        bne     kv_s16
        bra     kv_more
kv_m16:                                  | 2: 16-bit mono
        mvs.w   (%a0)+,%d0
        moveq   #14,%d1
        asl.l   %d1,%d0
        add.l   %d0,(%a4)+
        add.l   %d0,(%a4)+
        subq.l  #1,%d3
        bne     kv_m16
        bra     kv_more
kv_m24:                                  | 0: 24-bit mono
        move.l  (%a0),%d0
        addq.l  #3,%a0
        clr.b   %d0
        asr.l   #2,%d0
        add.l   %d0,(%a4)+
        add.l   %d0,(%a4)+
        subq.l  #1,%d3
        bne     kv_m24
        bra     kv_more
kv_s24:                                  | 1: 24-bit stereo
        move.l  (%a0),%d0
        clr.b   %d0
        asr.l   #2,%d0
        add.l   %d0,(%a4)+
        move.l  3(%a0),%d0
        clr.b   %d0
        asr.l   #2,%d0
        add.l   %d0,(%a4)+
        addq.l  #6,%a0
        subq.l  #1,%d3
        bne     kv_s24
kv_more:
        tst.l   %d5
        bne     kv_chunk
        bra     kv_store
kv_end:
        lea     T_V(%a3,%d4.l),%a0
        move.l  4(%a0),%d2               | position := end
kv_store:
        lea     T_V(%a3,%d4.l),%a0
        move.l  %d2,(%a0)
        movem.l (%sp),%d4/%a4
        addq.l  #8,%sp
kv_vnext:
        addq.l  #8,%d4
        moveq   #32,%d0
        cmp.l   %d0,%d4
        blt     kv_voice
        move.l  %a4,%a0                  | x4, saturated: each voice at unity
        move.l  %d6,%d0
        add.l   %d0,%d0                  | longs
        move.l  #0x1fffffff,%d2
        move.l  #-0x20000000,%d3
kv_sat:
        move.l  (%a0),%d1
        cmp.l   %d2,%d1
        ble     kv_sat1
        move.l  #0x7fffff00,%d1
        bra     kv_sat3
kv_sat1:
        cmp.l   %d3,%d1
        bge     kv_sat2
        move.l  #0x80000000,%d1
        bra     kv_sat3
kv_sat2:
        lsl.l   #2,%d1
        clr.b   %d1
kv_sat3:
        move.l  %d1,(%a0)+
        subq.l  #1,%d0
        bne     kv_sat
        rts

kv_name:
        .ascii  "KIT4"
        .align  4

| ---- state (RAM: the unit runs from DRAM): 8 tracks x 128 bytes ----------
kv_state:
        .fill   8 * T_STRIDE, 1, 0
kv_end_of_unit:
