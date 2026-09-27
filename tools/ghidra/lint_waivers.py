"""Findings `make lint-ghidra` accepts, each with its reason.

`check` is the finding's check and `key` the text after it in the LINT line:
the form for novel-form, the PROGRAM:ADDR site for the others. A waiver
says why the finding is safe and what evidence shows it, hardware first.
The lint lists the waivers an image did not need under DEBUG=1.
"""

WAIVERS = [
    # ---- ColdFire hooks whose output register is the point ----------------
    dict(check="reg-liveness", key="MAIN_OS:40005830", regs="A0",
         why="rig-hosts fx2_page1: a0 = the page-1 default of slot d2 read through the rig's id "
             "table instead of the DELAY descriptor (modules/rig-hosts/righosts.s)"),
    dict(check="reg-liveness", key="MAIN_OS:40005840", regs="A1",
         why="rig-hosts fx2_page2: a1 = the page-2 default of slot d2, as above"),
    dict(check="reg-liveness", key="MAIN_OS:40037840", regs="D6",
         why="scenes-p2: the FX2 page-2 knob draw shows a held scene's lock value; "
             "`d6 = the value to draw. Keeps everything but d6 and a0` (modules/scenes-p2/p2scenes.s)"),
    dict(check="reg-liveness", key="MAIN_OS:40037bdc", regs="D6",
         why="scenes-p2: the same for FX1's page-2 knob draw"),
    # ---- DSP encodings ------------------------------------------------------
    # Keys are parts (tools/ghidra/README.md): a parallel instruction's ALU op
    # and its move are waived separately.
    dict(check="novel-form", key='instr:[andi #%A;ccr|k15_8|3]()',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:00115d `andi # /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[div %A;%B|jj4;acc3|3](,)',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:00115f `div x0,a /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[lua {%A%B};%C|ea_r;LDisp;lua_d|3](,LDisp:[-%C|s13_11;k7_4;ndisp|3](,,),)',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:001890 `lua r03,-#,r03 /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='pm PM:[y:%B;%A|R5wS;EA|3](R5wS,EA:[%A|EAx|3](EAx:[{%A+%B}|ea_r;ea_n;ea_m|3](,,)))',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:000cc8 `move ,y:(r03+n),a /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='pm PM:[y:%B;%A|R5wS;EA|3](R5wS,EA:[>%A|ext24|6]())',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:000801 `move ,y:>#,a /2`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[move %B;x:{%A%C}|ea_r;R6r0;LDisp24;sext24|6](,R6r0,LDisp24:[-%B|sext24;nd|3](,),)',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_B:P:0009cf `move r#,r47,-# /2`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[move x:{%A%B};%C|ea_r;Disp7;D4w0|3](,Disp7:[-%C|s16_11;k6_6;ndisp|3](,,),D4w0)',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_B:P:0006c6 `move r47,-#,a /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[move x:{%A%C};%B|ea_r;R6w0;LDisp24;sext24|6](,R6w0,LDisp24:[-%B|sext24;nd|3](,),)',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_B:P:0009c9 `move r47,-#,r# /2`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[move %C;x:{%A%B}|ea_r;Disp7;D4r0|3](,Disp7:[-%C|s16_11;k6_6;ndisp|3](,,),D4r0)',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_B:P:000702 `move x#,r47,-# /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='alu or ALU:[%A;%B|jj4;acc3|3](,) ALUm ALUW:[|acc3|3]()',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:000acf `or y1,a, /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:[rep %A|Cnt12|3](Cnt12:[#%C|k3_0;k15_8;cnt|3](,,))',
         why="BASELINE, unreviewed: ships in upstream main 68af650 (bamsep26), e.g. DSP_A:P:00115e `rep ## /1`; needs hardware evidence or a rewrite to a stock form"),
]
