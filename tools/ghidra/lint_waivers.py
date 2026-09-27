"""Findings `make lint-ghidra` accepts, each with its reason.

`check` is the finding's check and `key` the text after it in the LINT line:
the form for novel-form, the PROGRAM:ADDR site for the others. A waiver
says why the finding is safe and what evidence shows it, hardware first.
The lint lists the waivers an image did not need under DEBUG=1.
"""

WAIVERS = [
    dict(check="novel-form", key='instr:955(ALU:760(,),ALUm,ALUW:835(),PM:860(R5wS,EA:148(EAx:143())))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:0019df `add a,b,x:(r03),x# /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1090()',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:001180 `andi # /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1155(,)',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:001182 `div x0,a /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU,ALUm,ALUW,PM:863(R5rS,EA:148(EAx:144(,,))))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:000f09 `move ,a,y:(r47+n) /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU,ALUm,ALUW,PM:862(R5wS,EA:148(EAx:144(,,))))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:000ccf `move ,y:(r03+n),a /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU,ALUm,ALUW,PM:862(R5wS,EA:149()))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:000801 `move ,y:>#,a /2`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1232(,R6r0,LDisp24:1230(,),)',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_B:P:0009cf `move r#,r47,-# /2`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1238(,Disp7:1237(,,),D4w0)',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_B:P:0006c6 `move r47,-#,a /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1231(,R6w0,LDisp24:1230(,),)',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_B:P:0009c9 `move r47,-#,r# /2`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1239(,Disp7:1237(,,),D4r0)',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_B:P:000702 `move x#,r47,-# /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU:818(MulQ,),ALUm,ALUW:835(),PM:860(R5wS,EA:148(EAx:144(,,))))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:001c16 `mpy x#,y#,a,x:(r03+n),x# /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU:806(,),ALUm,ALUW:835(),PM)',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:000ac7 `or y1,a, /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:1424(Cnt12:1012(,,))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:001181 `rep ## /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU:768(,),ALUm,ALUW:835(),PM:860(R5wS,EA:148(EAx:143())))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:0019b1 `sub b,a,x:(r03),x# /1`; needs hardware evidence or a rewrite to a stock form"),
    dict(check="novel-form", key='instr:955(ALU:804(,S56j:721(),),ALUm,ALUW:835(),PM:861(R5rS,EA:148(EAx:141(,))))',
         why="BASELINE, unreviewed: ships in main 0b6204c (bamsep26), e.g. DSP_A:P:0019c8 `tfr x0,a,b,x:(r03)- /1`; needs hardware evidence or a rewrite to a stock form"),
]
