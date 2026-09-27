// Hook checks on a built ColdFire image, against the stock MAIN_OS the project
// holds.  analyzeHeadless -process -readOnly -noanalysis -postScript
// OtLintCf.java DIR: for the 68000 program it reads DIR/PROGRAM.in and writes
// DIR/PROGRAM.out; other programs are skipped.  Nothing is saved.
//
// Input (PROGRAM.in), one directive per line:
//   image 0xBASE PATH          the built image, loaded at BASE
//   dram 0xADDR PATH           a runtime the loader unpacks to ADDR at boot
//
// Output, tab-separated:
//   finding CHECK ADDR TEXT REGS   hook-boundary | branch-into-span | detour-target |
//                              reg-liveness (REGS: the registers it names)
//   note TEXT
//
// A changed run whose first byte is stock code is a patched site.  Where the
// built code there is a `jsr` or `jmp` to an absolute address, the site is a
// hook: the stock instructions it overwrote are the displaced span, and the
// code it reaches (a cave, a linked unit, a DRAM runtime) is followed by a
// small symbolic interpreter over p-code until control comes back to stock.
// Every register byte and flag live there (stock liveness, before the build's
// bytes go in) must hold what the displaced span would have left in it:
// unchanged, or the same expression of the entry state.  A callee is
// summarised by the same interpreter (what it preserves, how it moves SP),
// falling back to the ABI (d0/d1/a0/a1 and the flags scratch).
//
// DEBUG set in the environment prints each finding as it is made.
//@category octabam
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

public class OtLintCf extends GhidraScript {

	private PrintWriter out;
	private boolean debug;
	private int findings;
	private Listing listing;
	private Memory mem;
	private AddressSpace ram;

	@Override
	public void run() throws Exception {
		if (!currentProgram.getLanguage().getProcessor().toString().equals("68000")) {
			return;
		}
		String[] args = getScriptArgs();
		if (args.length != 1) {
			printerr("OtLintCf: usage: OtLintCf.java <dir holding PROGRAM.in>");
			return;
		}
		debug = System.getenv("DEBUG") != null && !System.getenv("DEBUG").isEmpty();
		File input = new File(args[0], currentProgram.getName() + ".in");
		if (!input.exists()) {
			println("OtLintCf: " + currentProgram.getName() + ": no " + input.getName() + ", skipped");
			return;
		}
		listing = currentProgram.getListing();
		mem = currentProgram.getMemory();
		ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
		initRegs();
		out = new PrintWriter(new File(args[0], currentProgram.getName() + ".out"), "UTF-8");
		try {
			lint(input);
		}
		finally {
			out.close();
		}
		println(String.format("OtLintCf: %s: %d findings", currentProgram.getName(), findings));
	}

	// ---- the sites --------------------------------------------------------

	/** One changed run in stock code, and what stock knew about it. */
	private static final class Site {
		Address start;                 // the stock instruction holding the first changed byte
		Address changedEnd;            // the last changed byte
		Address stockEnd;              // the first stock boundary after changedEnd
		List<Address> interior = new ArrayList<>();   // stock instruction starts inside
		Map<Address, List<Address>> refsIn = new HashMap<>();
		Map<Address, BitSet> liveAt = new HashMap<>();
		Map<Address, St> stockExit = new HashMap<>();  // the displaced span's exits
		St stockReturn;                // stock from the site to its routine's return
		Set<Address> bounds = new HashSet<>();         // stock instruction starts, stockEnd too
		String stockText = "";
	}

	private void lint(File input) throws Exception {
		long base = -1;
		File image = null;
		List<Object[]> dram = new ArrayList<>();
		for (String line : Files.readAllLines(input.toPath())) {
			String[] f = line.trim().split("\\s+");
			if (f.length == 0 || f[0].isEmpty() || f[0].startsWith("#")) {
				continue;
			}
			switch (f[0]) {
				case "image" -> {
					base = Long.decode(f[1]);
					image = new File(input.getParentFile(), f[2]);
				}
				case "dram" -> dram.add(new Object[] { Long.decode(f[1]),
					new File(input.getParentFile(), f[2]) });
				default -> throw new IllegalArgumentException("unknown directive: " + line);
			}
		}
		byte[] built = Files.readAllBytes(image.toPath());

		// Changed runs over the stock image.  A run is extended while the
		// built instructions over it overlap the next run: a jsr's operand can
		// equal the stock bytes it overwrote, which splits one patch in two.
		MemoryBlock img = mem.getBlock(ram.getAddress(base));
		long stockLen = img.getEnd().getOffset() - base + 1;
		byte[] stock = new byte[(int) stockLen];
		mem.getBytes(ram.getAddress(base), stock);
		List<long[]> runs = new ArrayList<>();
		for (int i = 0; i < stockLen; i++) {
			if (stock[i] == built[i]) {
				continue;
			}
			if (!runs.isEmpty() && base + i - runs.get(runs.size() - 1)[1] < 2) {
				runs.get(runs.size() - 1)[1] = base + i;
			}
			else {
				runs.add(new long[] { base + i, base + i });
			}
		}

		for (int r = 0; r + 1 < runs.size(); r++) {
			long[] cur = runs.get(r);
			Instruction st = listing.getInstructionContaining(ram.getAddress(cur[0]));
			if (st == null) {
				continue;
			}
			long a = st.getAddress().getOffset();
			while (a <= cur[1]) {
				int n = builtLength(built, base, a);
				if (n <= 0) {
					break;
				}
				a += n;
			}
			if (a > runs.get(r + 1)[0]) {
				cur[1] = runs.get(r + 1)[1];
				runs.remove(r + 1);
				r--;
			}
		}

		// New code lives in stock zeros, past the image, or in a DRAM runtime.
		AddressSet region = new AddressSet();
		List<Site> sites = new ArrayList<>();
		int data = 0;
		for (long[] r : runs) {
			Address a = ram.getAddress(r[0]), e = ram.getAddress(r[1]);
			boolean zero = true;
			for (long k = r[0]; k <= r[1]; k++) {
				zero &= stock[(int) (k - base)] == 0;
			}
			Instruction first = null;
			for (Address x = a; x.compareTo(e) <= 0 && first == null; x = x.next()) {
				first = listing.getInstructionContaining(x);
			}
			if (first != null) {
				Site s = new Site();
				s.start = first.getAddress().compareTo(a) < 0 ? first.getAddress() : a;
				Instruction st = listing.getInstructionContaining(s.start);
				s.start = st != null ? st.getAddress() : s.start;
				s.changedEnd = e;
				sites.add(s);
			}
			else if (zero) {
				region.add(a, e);
			}
			else {
				data++;
			}
		}
		// A cave keeps zero bytes of its own (a word of data, `ori.b #0`), so
		// runs with nothing but stock zeros between them are one cave.
		List<AddressRange> rs = new ArrayList<>();
		region.forEach(rs::add);
		for (int k = 0; k + 1 < rs.size(); k++) {
			long from = rs.get(k).getMaxAddress().getOffset() + 1, to = rs.get(k + 1).getMinAddress().getOffset();
			boolean zeros = to - from < 256;
			for (long q = from; zeros && q < to; q++) {
				zeros = stock[(int) (q - base)] == 0;
			}
			if (zeros) {
				region.add(ram.getAddress(from), ram.getAddress(to - 1));
			}
		}
		if (built.length > stockLen) {
			region.add(ram.getAddress(base + stockLen), ram.getAddress(base + built.length - 1));
		}
		for (Object[] d : dram) {
			long at = (Long) d[0];
			long n = ((File) d[1]).length();
			region.add(ram.getAddress(at), ram.getAddress(at + n - 1));
		}
		out.println("note\t" + runs.size() + " changed runs: " + sites.size() + " in stock code, " +
			data + " in stock data; new code " + region.getNumAddresses() + " bytes");

		// What stock says about each site, before anything changes.
		for (Site s : sites) {
			Instruction last = listing.getInstructionContaining(s.changedEnd);
			s.stockEnd = last != null ? last.getMaxAddress().next() : s.changedEnd.next();
			StringBuilder txt = new StringBuilder();
			for (Instruction in = listing.getInstructionAt(s.start); in != null &&
				in.getAddress().compareTo(s.stockEnd) < 0; in = in.getNext()) {
				txt.append(txt.length() > 0 ? "; " : "").append(in);
				if (!in.getAddress().equals(s.start)) {
					s.interior.add(in.getAddress());
					List<Address> from = new ArrayList<>();
					for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(in.getAddress())) {
						Address f = ref.getFromAddress();
						if (f.compareTo(s.start) >= 0 && f.compareTo(s.stockEnd) < 0) {
							continue;
						}
						if (ref.getReferenceType().isFlow() || ref.getReferenceType().isData()) {
							from.add(f);
						}
					}
					if (!from.isEmpty()) {
						s.refsIn.put(in.getAddress(), from);
					}
				}
			}
			s.stockText = txt.toString();
			for (Instruction in = listing.getInstructionAt(s.start); in != null &&
				in.getAddress().compareTo(s.stockEnd) <= 0; in = in.getNext()) {
				s.bounds.add(in.getAddress());
			}
			s.bounds.add(s.stockEnd);
			Run ret = new Run(null, null);
			ret.go(s.start, St.entry());
			s.stockReturn = ret.gaveUp == null ? ret.returns : null;
			// Liveness at the span's end and the next few stock boundaries.
			Address b = s.stockEnd;
			for (int k = 0; k < 4 && b != null; k++) {
				s.liveAt.put(b, liveIn(b));
				Instruction nx = listing.getInstructionAt(b);
				b = nx != null ? nx.getMaxAddress().next() : null;
			}
			// The displaced span, run symbolically from the stock state.
			Run run = new Run(null, new AddressSet(s.start, s.stockEnd.previous()));
			run.go(s.start, St.entry());
			for (Map.Entry<Address, St> x : run.exits.entrySet()) {
				s.stockExit.put(x.getKey(), x.getValue());
			}
		}
		liveMemo.clear();
		summaries.clear();

		// Write the built image and the DRAM runtimes, clearing stock code
		// over every changed run.
		for (Site s : sites) {
			Instruction last = listing.getInstructionContaining(s.changedEnd);
			Address end = last != null ? last.getMaxAddress() : s.changedEnd;
			listing.clearCodeUnits(s.start, end, false);
		}
		for (long[] r : runs) {
			listing.clearCodeUnits(ram.getAddress(r[0]), ram.getAddress(r[1]), false);
			byte[] b = Arrays.copyOfRange(built, (int) (r[0] - base), (int) (r[1] - base + 1));
			mem.setBytes(ram.getAddress(r[0]), b);
		}
		if (built.length > stockLen) {
			Address at = ram.getAddress(base + stockLen);
			initialize(at, built.length - stockLen);
			mem.setBytes(at, Arrays.copyOfRange(built, (int) stockLen, built.length));
		}
		for (Object[] d : dram) {
			Address at = ram.getAddress((Long) d[0]);
			byte[] b = Files.readAllBytes(((File) d[1]).toPath());
			initialize(at, b.length);
			mem.setBytes(at, b);
		}
		AddressSet seeds = new AddressSet();
		for (Site s : sites) {
			seeds.add(s.start);
		}
		new DisassembleCommand(seeds, null, true).applyTo(currentProgram, monitor);

		for (Site s : sites) {
			checkSite(s, region);
		}
		checkRegionTargets(region);
	}

	/** The length of the built instruction at `a`, decoded from the built bytes; 0 if none. */
	private int builtLength(byte[] built, long base, long a) {
		int i = (int) (a - base);
		if (i < 0 || i + 2 > built.length) {
			return 0;
		}
		byte[] b = Arrays.copyOfRange(built, i, Math.min(built.length, i + 16));
		try {
			var buf = new ghidra.program.model.mem.ByteMemBufferImpl(ram.getAddress(a), b, true);
			var ctx = new ghidra.program.model.lang.ProcessorContextImpl(currentProgram.getLanguage());
			return currentProgram.getLanguage().parse(buf, ctx, false).getLength();
		}
		catch (Exception e) {
			return 0;
		}
	}

	/** Make [at, at+n) initialized memory (the SDRAM past the image starts out empty). */
	private void initialize(Address at, long n) throws Exception {
		MemoryBlock b = mem.getBlock(at);
		if (b == null) {
			throw new IllegalStateException("no memory block at " + at);
		}
		if (b.isInitialized()) {
			return;
		}
		if (b.getStart().compareTo(at) < 0) {
			mem.split(b, at);
			b = mem.getBlock(at);
		}
		Address end = at.add(n);
		if (b.getEnd().compareTo(end) > 0) {
			mem.split(b, end);
			b = mem.getBlock(at);
		}
		mem.convertToInitialized(b, (byte) 0);
	}

	private void checkSite(Site s, AddressSet region) {
		// Decode the built code from the site until it passes the changed bytes.
		Instruction first = listing.getInstructionAt(s.start);
		if (first == null) {
			finding("hook-boundary", s.start, "the built bytes at the site do not decode (stock: " +
				s.stockText + ")");
			return;
		}
		Address a = s.start;
		Instruction in = first;
		while (in != null && in.getAddress().compareTo(s.changedEnd) <= 0) {
			a = in.getMaxAddress().next();
			in = listing.getInstructionAt(a);
			if (in == null && a.compareTo(s.changedEnd) <= 0 &&
				listing.getInstructionContaining(a) == null) {
				new DisassembleCommand(a, null, false).applyTo(currentProgram, monitor);
				in = listing.getInstructionAt(a);
			}
			if (in == null && a.compareTo(s.changedEnd) <= 0) {
				finding("hook-boundary", a, "the built bytes stop decoding inside the patch (stock: " +
					s.stockText + ")");
				return;
			}
		}
		Address end = a;               // first built boundary past the changed bytes
		if (!s.bounds.contains(end) && !s.liveAt.containsKey(end)) {
			Instruction lastBuilt = listing.getInstructionBefore(end);
			if (lastBuilt == null || lastBuilt.hasFallthrough()) {
				finding("hook-boundary", s.start, "the patch ends at " + end +
					", inside a stock instruction (the displaced span " + s.start + ".." +
					s.stockEnd.previous() + " is " + s.stockText + "); the rest runs as a new instruction");
				return;
			}
			end = s.stockEnd;          // a jmp: the tail of the split instruction is dead
		}
		for (Map.Entry<Address, List<Address>> e : s.refsIn.entrySet()) {
			if (e.getKey().compareTo(end) < 0) {
				finding("branch-into-span", e.getKey(), "stock reaches " + e.getKey() + " from " +
					e.getValue() + ", but the patch at " + s.start + " overwrote that instruction (" +
					s.stockText + ")");
			}
		}

		// A hook: jsr/jmp to an absolute address.
		byte[] op = new byte[2];
		try {
			mem.getBytes(s.start, op);
		}
		catch (Exception x) {
			return;
		}
		int opc = ((op[0] & 0xff) << 8) | (op[1] & 0xff);
		if ((opc != 0x4eb9 && opc != 0x4ef9) || first.getLength() != 6) {
			return;                    // an operand or immediate rewritten in place
		}
		Address target = first.getAddress(0) != null ? first.getAddress(0) : null;
		if (target == null) {
			Address[] fl = first.getFlows();
			target = fl.length > 0 ? fl[0] : null;
		}
		if (target == null) {
			return;
		}
		String why = targetProblem(target, region, true);
		if (why != null) {
			finding("detour-target", s.start, "`" + first + "` -> " + target + ": " + why);
			return;
		}
		if (!region.contains(target)) {
			note(s.start + ": `" + first + "` goes straight to stock " + target + "; not followed");
			return;
		}

		// Follow the cave from its entry with the state the hook hands it.
		St st = St.entry();
		if (opc == 0x4eb9) {
			T sp = st.read(SP_OFF, 4);
			T nsp = T.add(sp, -4, 4);
			st.write(SP_OFF, 4, nsp);
			st.store(nsp, T.cnst(s.start.getOffset() + 6, 4));
		}
		AddressSet inside = new AddressSet(region);
		// Built code between the jsr's return and the span's end (the nop pad).
		if (opc == 0x4eb9 && s.start.add(6).compareTo(end) < 0) {
			inside.add(s.start.add(6), end.previous());
		}
		Run run = new Run(region, inside);
		run.go(target, st);
		if (run.gaveUp != null) {
			note(s.start + ": the cave at " + target + " was not followed to its end (" + run.gaveUp + ")");
			return;
		}
		if (run.callerReturn != null) {
			// It returns for the hooked routine: the routine's caller gets its
			// callee-saved registers back and SP just above the return slot.
			List<String> bad = new ArrayList<>();
			for (Register r : REPORT) {
				int off = (int) r.getAddress().getOffset();
				if (!calleeSaved.get(off)) {
					continue;
				}
				for (int k = 0; k < r.getMinimumByteSize(); k++) {
					if (!run.callerReturn.readByte(off + k).equals(new T("init", off + k, 1))) {
						bad.add(r.getName());
						break;
					}
				}
			}
			T sp = run.callerReturn.read(SP_OFF, 4);
			T want = T.add(run.callerSlot, 4, 4);
			if (s.stockReturn != null) {
				// Compare with stock's own way out from the site: the saved
				// registers come back from the frame, SP from its epilogue.
				bad.clear();
				for (Register r : REPORT) {
					int off = (int) r.getAddress().getOffset();
					if (!calleeSaved.get(off)) {
						continue;
					}
					for (int k = 0; k < r.getMinimumByteSize(); k++) {
						if (!run.callerReturn.readByte(off + k).equals(s.stockReturn.readByte(off + k))) {
							bad.add(r.getName());
							break;
						}
					}
				}
				want = s.stockReturn.read(SP_OFF, 4);
			}
			else if (!isEntry(s.start)) {
				bad.clear();
				note(s.start + ": the cave at " + target + " returns for the hooked routine mid-routine, " +
					"and stock from the site was not followed to its return; not compared");
				want = sp;
			}
			if (!sp.equals(want)) {
				bad.add("SP");
			}
			if (!bad.isEmpty()) {
				finding("reg-liveness", s.start, "the cave at " + target + " returns for the hooked routine " +
					"straight to its caller, and leaves " + String.join(" ", bad) +
					" not as the caller had them", bad);
			}
		}
		for (Map.Entry<Address, St> x : run.exits.entrySet()) {
			Address to = x.getKey();
			St stockSt = s.stockExit.get(to);
			BitSet live = s.liveAt.get(to);
			if (to == null || live == null || stockSt == null) {
				note(s.start + ": the cave at " + target + " comes back to " + to +
					", which the displaced span never reaches; not compared");
				continue;
			}
			List<String> bad = new ArrayList<>();
			for (Register r : REPORT) {
				int off = (int) r.getAddress().getOffset();
				for (int k = 0; k < r.getMinimumByteSize(); k++) {
					if (!live.get(off + k)) {
						continue;
					}
					T want = stockSt.readByte(off + k), got = x.getValue().readByte(off + k);
					if (want.mentions("call")) {
						continue;              // a displaced call's result: the cave may replace it
					}
					if (!want.equals(got)) {
						bad.add(r.getName());
						break;
					}
				}
			}
			if (!bad.isEmpty()) {
				finding("reg-liveness", s.start, "after the hook returns to " + to + ", " +
					String.join(" ", bad) + (bad.size() == 1 ? " is" : " are") +
					" live, and the cave at " + target + " leaves " + (bad.size() == 1 ? "it" : "them") +
					" different from what the displaced code (" + s.stockText + ") leaves", bad);
			}
		}
	}

	/** Flow targets from new code: an instruction start, and not mid-routine in new code. */
	private void checkRegionTargets(AddressSet region) {
		for (AddressRange r : region) {
			for (Instruction in = listing.getInstructionAfter(r.getMinAddress().previous()); in != null &&
				in.getAddress().compareTo(r.getMaxAddress()) <= 0; in = in.getNext()) {
				for (Address t : in.getFlows()) {
					if (region.contains(t) && region.contains(in.getAddress()) &&
						sameRange(region, t, in.getAddress())) {
						continue;          // inside one routine
					}
					String why = targetProblem(t, region, in.getFlowType().isCall());
					if (why != null) {
						finding("detour-target", in.getAddress(), "`" + in + "` -> " + t + ": " + why);
					}
				}
			}
		}
	}

	private static boolean sameRange(AddressSet set, Address a, Address b) {
		AddressRange r = set.getRangeContaining(a);
		return r != null && r.contains(b);
	}

	/** Why `t` is no place to go; `entry`: a call or a hook, which needs a routine's start. */
	private String targetProblem(Address t, AddressSet region, boolean entry) {
		if (!mem.contains(t) || !mem.getBlock(t).isInitialized()) {
			return "no code is there";
		}
		Instruction at = listing.getInstructionAt(t);
		if (at == null) {
			Instruction c = listing.getInstructionContaining(t);
			if (c != null) {
				return "inside `" + c + "` at " + c.getAddress();
			}
			new DisassembleCommand(t, null, true).applyTo(currentProgram, monitor);
			at = listing.getInstructionAt(t);
			if (at == null) {
				return "does not decode";
			}
		}
		if (entry && region.contains(t)) {
			AddressRange r = region.getRangeContaining(t);
			if (!t.equals(r.getMinAddress())) {
				Instruction prev = listing.getInstructionBefore(t);
				if (prev != null && prev.getMaxAddress().next().equals(t) && prev.hasFallthrough() &&
					isRealCode(prev)) {
					return "mid-routine: `" + prev + "` at " + prev.getAddress() + " falls through into it";
				}
			}
		}
		return null;
	}

	/** Zero padding decodes as `ori.b #0,d0`; that is not code falling through. */
	private boolean isRealCode(Instruction in) {
		try {
			for (byte b : in.getBytes()) {
				if (b != 0) {
					return true;
				}
			}
		}
		catch (Exception e) {
			return true;
		}
		return false;
	}

	// ---- registers --------------------------------------------------------

	private static final String[] NAMES = { "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "A0",
		"A1", "A2", "A3", "A4", "A5", "A6", "SP", "XF", "NF", "ZF", "VF", "CF" };
	private static final String[] SCRATCH = { "D0", "D1", "A0", "A1", "XF", "NF", "ZF", "VF", "CF" };
	private static final String[] AT_RETURN = { "D0", "D2", "D3", "D4", "D5", "D6", "D7", "A2", "A3",
		"A4", "A5", "A6", "SP" };
	private final List<Register> REPORT = new ArrayList<>();
	private final BitSet tracked = new BitSet(), scratch = new BitSet(), atReturn = new BitSet();
	private final BitSet flags = new BitSet(), calleeSaved = new BitSet();
	private static int SP_OFF;
	private int xfOff;

	private void initRegs() {
		for (String n : NAMES) {
			Register r = currentProgram.getRegister(n);
			REPORT.add(r);
			set(tracked, r);
		}
		for (String n : SCRATCH) {
			set(scratch, currentProgram.getRegister(n));
		}
		for (String n : AT_RETURN) {
			set(atReturn, currentProgram.getRegister(n));
		}
		SP_OFF = (int) currentProgram.getRegister("SP").getAddress().getOffset();
		xfOff = (int) currentProgram.getRegister("XF").getAddress().getOffset();
		for (String n : new String[] { "XF", "NF", "ZF", "VF", "CF" }) {
			set(flags, currentProgram.getRegister(n));
		}
		for (String n : new String[] { "D2", "D3", "D4", "D5", "D6", "D7", "A2", "A3", "A4", "A5", "A6" }) {
			set(calleeSaved, currentProgram.getRegister(n));
		}
	}

	private static void set(BitSet b, Register r) {
		int off = (int) r.getAddress().getOffset();
		b.set(off, off + r.getMinimumByteSize());
	}

	private BitSet bytes(Varnode v) {
		BitSet b = new BitSet();
		if (v != null && v.isRegister()) {
			b.set((int) v.getOffset(), (int) v.getOffset() + v.getSize());
			b.and(tracked);
		}
		return b;
	}

	// ---- liveness (stock) -------------------------------------------------

	private static final int BUDGET = 20000;
	private final Map<Address, BitSet> liveMemo = new HashMap<>();

	private BitSet[] genKill(Instruction in) {
		BitSet gen = new BitSet(), kill = new BitSet();
		for (PcodeOp op : in.getPcode()) {
			int oc = op.getOpcode();
			int first = (oc == PcodeOp.BRANCH || oc == PcodeOp.CBRANCH || oc == PcodeOp.CALL) ? 1 : 0;
			for (int i = first; i < op.getNumInputs(); i++) {
				BitSet r = bytes(op.getInput(i));
				r.andNot(kill);
				gen.or(r);
			}
			kill.or(bytes(op.getOutput()));
			if (oc == PcodeOp.RETURN) {
				BitSet r = (BitSet) atReturn.clone();
				r.andNot(kill);
				gen.or(r);
			}
		}
		// Flags read wholesale (packed into SR/CCR: `move sr,dn` around an
		// interrupt mask) are not consumed; X is consumed only by the extend
		// arithmetic and the rotates through X.
		BitSet fl = (BitSet) gen.clone();
		fl.and(flags);
		if (fl.cardinality() >= 4) {
			gen.andNot(flags);
		}
		if (!in.getMnemonicString().toLowerCase().matches("(addx|subx|negx|roxl|roxr|abcd|sbcd|nbcd).*")) {
			gen.clear(xfOff);
		}
		if (in.getFlowType().isCall()) {
			kill.or(scratch);          // the callee may clobber the ABI's scratch
			BitSet keep = (BitSet) kill.clone();
			for (Address c : in.getFlows()) {
				BitSet r = (BitSet) liveIn(c).clone();
				r.andNot(calleeSaved);     // a prologue saving d2-d7/a2-a6 does not use them
				gen.or(r);
			}
			kill = keep;
		}
		if (in.getFlowType().isComputed() && in.getFlowType().isJump() && in.getFlows().length == 0) {
			gen.or(atReturn);          // an unresolved jump: assume the caller's registers matter
		}
		return new BitSet[] { gen, kill };
	}

	private static List<Address> successors(Instruction in) {
		List<Address> l = new ArrayList<>();
		if (!in.getFlowType().isCall()) {
			Collections.addAll(l, in.getFlows());
		}
		if (in.getFallThrough() != null) {
			l.add(in.getFallThrough());
		}
		return l;
	}

	/** Register bytes read before written on some path from `start` to the return. */
	private BitSet liveIn(Address start) {
		BitSet memo = liveMemo.get(start);
		if (memo != null) {
			return memo;
		}
		liveMemo.put(start, (BitSet) atReturn.clone());   // recursion: assume the ABI
		Map<Address, Instruction> nodes = new LinkedHashMap<>();
		ArrayDeque<Address> work = new ArrayDeque<>(List.of(start));
		while (!work.isEmpty() && nodes.size() < BUDGET) {
			Address a = work.pop();
			Instruction in = listing.getInstructionAt(a);
			if (in == null || nodes.containsKey(a)) {
				continue;
			}
			nodes.put(a, in);
			work.addAll(successors(in));
		}
		Map<Address, BitSet[]> gk = new HashMap<>();
		for (Instruction in : nodes.values()) {
			gk.put(in.getAddress(), genKill(in));
		}
		Map<Address, BitSet> live = new HashMap<>();
		List<Instruction> order = new ArrayList<>(nodes.values());
		Collections.reverse(order);
		boolean moved = true;
		while (moved) {
			moved = false;
			for (Instruction in : order) {
				BitSet o = new BitSet();
				for (Address s : successors(in)) {
					BitSet l = live.get(s);
					if (l != null) {
						o.or(l);
					}
					else if (!nodes.containsKey(s)) {
						o.or(atReturn);    // off the explored graph
					}
				}
				BitSet[] g = gk.get(in.getAddress());
				o.andNot(g[1]);
				o.or(g[0]);
				if (!o.equals(live.get(in.getAddress()))) {
					live.put(in.getAddress(), o);
					moved = true;
				}
			}
		}
		BitSet r = live.getOrDefault(start, (BitSet) atReturn.clone());
		liveMemo.put(start, r);
		return r;
	}

	// ---- the symbolic interpreter ------------------------------------------

	/** An expression over the entry state, hash-consed by structure. */
	static final class T {
		final String op;
		final long k;
		final int size;
		final T[] a;
		private final int h;

		T(String op, long k, int size, T... a) {
			this.op = op;
			this.k = k;
			this.size = size;
			this.a = a;
			this.h = Objects.hash(op, k, size, Arrays.hashCode(a));
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof T t && t.h == h && t.op.equals(op) && t.k == k && t.size == size &&
				Arrays.equals(t.a, a);
		}

		@Override
		public int hashCode() {
			return h;
		}

		boolean mentions(String o) {
			if (op.equals(o)) {
				return true;
			}
			for (T x : a) {
				if (x.mentions(o)) {
					return true;
				}
			}
			return false;
		}

		static long mask(int size) {
			return size >= 8 ? -1L : (1L << (8 * size)) - 1;
		}

		static T cnst(long v, int size) {
			return new T("c", v & mask(size), size);
		}

		boolean isConst() {
			return op.equals("c");
		}

		static T add(T x, long c, int size) {
			if (x.isConst()) {
				return cnst(x.k + c, size);
			}
			if (x.op.equals("add")) {
				return add(x.a[0], x.a[1].k + c, size);
			}
			if ((c & mask(size)) == 0) {
				return x;
			}
			return new T("add", 0, size, x, cnst(c, size));
		}

		@Override
		public String toString() {
			if (isConst()) {
				return "0x" + Long.toHexString(k);
			}
			StringBuilder s = new StringBuilder(op).append(k != 0 ? "" + k : "");
			if (a.length > 0) {
				s.append('(');
				for (int i = 0; i < a.length; i++) {
					s.append(i > 0 ? "," : "").append(a[i]);
				}
				s.append(')');
			}
			return s.toString();
		}
	}

	/** Register bytes (absent = the entry value) and memory by address expression. */
	static final class St {
		final Map<Integer, T> regs = new HashMap<>();
		final Map<T, T> mem = new HashMap<>();
		final Map<Long, Integer> calls = new HashMap<>();

		static St entry() {
			return new St();
		}

		St copy() {
			St s = new St();
			s.regs.putAll(regs);
			s.mem.putAll(mem);
			s.calls.putAll(calls);
			return s;
		}

		T readByte(int off) {
			return regs.getOrDefault(off, new T("init", off, 1));
		}

		T read(int off, int size) {
			T[] b = new T[size];
			boolean init = true, same = true;
			for (int i = 0; i < size; i++) {
				b[i] = readByte(off + i);
				init &= b[i].op.equals("init") && b[i].k == off + i;
				same &= b[i].op.equals("byte") && b[i].k == i && b[i].a[0].size == size &&
					b[i].a[0].equals(b[0].a.length > 0 ? b[0].a[0] : null);
			}
			if (init) {
				return new T("sym", off, size);
			}
			if (same) {
				return b[0].a[0];
			}
			return new T("piece", 0, size, b);
		}

		void write(int off, int size, T v) {
			for (int i = 0; i < size; i++) {
				T b;
				if (v.op.equals("sym") && v.size == size) {
					b = new T("init", v.k + i, 1);
				}
				else if (v.op.equals("piece") && v.a.length == size) {
					b = v.a[i];
				}
				else if (size == 1 && (v.op.equals("init") || v.op.equals("byte"))) {
					b = v;
				}
				else {
					b = new T("byte", i, 1, v);
				}
				if (b.op.equals("init") && b.k == off + i) {
					regs.remove(off + i);
				}
				else {
					regs.put(off + i, b);
				}
			}
		}

		T load(T addr, int size) {
			T v = mem.get(addr);
			return v != null && v.size == size ? v : new T("load", 0, size, addr);
		}

		void store(T addr, T v) {
			mem.put(addr, v);
		}

		/** The join at `at`: what differs becomes a value of its own. */
		St join(St o, Address at) {
			St s = new St();
			Set<Integer> keys = new HashSet<>(regs.keySet());
			keys.addAll(o.regs.keySet());
			for (int k : keys) {
				T x = readByte(k), y = o.readByte(k);
				s.regs.put(k, x.equals(y) ? x : new T("unk", k, 1, T.cnst(at.getOffset(), 4)));
				if (s.regs.get(k).op.equals("init") && s.regs.get(k).k == k) {
					s.regs.remove(k);
				}
			}
			Set<T> mk = new HashSet<>(mem.keySet());
			mk.addAll(o.mem.keySet());
			for (T k : mk) {
				T x = mem.get(k), y = o.mem.get(k);
				s.mem.put(k, Objects.equals(x, y) ? x
						: new T("unkm", 0, x != null ? x.size : y.size, k, T.cnst(at.getOffset(), 4)));
			}
			s.calls.putAll(calls);
			o.calls.forEach((k, v) -> s.calls.merge(k, v, Math::max));
			return s;
		}

		@Override
		public boolean equals(Object o) {
			return o instanceof St s && s.regs.equals(regs) && s.mem.equals(mem);
		}

		@Override
		public int hashCode() {
			return regs.hashCode() * 31 + mem.hashCode();
		}
	}

	/** What a callee does to its caller's registers. */
	private static final class Summary {
		BitSet clobbered = new BitSet();
		long spDelta = 4;               // rts pops the return address
	}

	private final Map<Address, Summary> summaries = new HashMap<>();
	private int depth;

	private Summary summarize(Address callee) {
		Summary memo = summaries.get(callee);
		if (memo != null) {
			return memo;
		}
		Summary abi = new Summary();
		abi.clobbered.or(scratch);
		summaries.put(callee, abi);                 // recursion: the ABI
		if (depth > 8 || listing.getInstructionAt(callee) == null) {
			return abi;
		}
		depth++;
		try {
			Run run = new Run(null, null);
			run.go(callee, St.entry());
			if (run.gaveUp != null || run.returns == null) {
				return abi;
			}
			Summary s = new Summary();
			for (int off = tracked.nextSetBit(0); off >= 0; off = tracked.nextSetBit(off + 1)) {
				T b = run.returns.readByte(off);
				if (!(b.op.equals("init") && b.k == off)) {
					s.clobbered.set(off);
				}
			}
			T sp = run.returns.read(SP_OFF, 4);
			if (sp.op.equals("sym") && sp.k == SP_OFF) {
				s.spDelta = 0;
			}
			else if (sp.op.equals("add") && sp.a[0].op.equals("sym") && sp.a[0].k == SP_OFF) {
				long d = sp.a[1].k;
				s.spDelta = (d << 32) >> 32;
			}
			else {
				return abi;
			}
			s.clobbered.clear(SP_OFF, SP_OFF + 4);
			summaries.put(callee, s);
			return s;
		}
		finally {
			depth--;
		}
	}

	/**
	 * One symbolic run.  `inside` null: a callee, followed until it returns
	 * (every flow is inside).  Otherwise control leaving `inside` (not by a
	 * call) is an exit, collected by address.
	 */
	private final class Run {
		final AddressSet region;
		final AddressSet inside;
		final Map<Address, St> at = new HashMap<>();
		final Map<Address, Integer> visits = new HashMap<>();
		final Map<Address, St> exits = new LinkedHashMap<>();
		St returns;
		St callerReturn;                // hook mode: the cave returned for the hooked routine
		T callerSlot;                   // ... through this stack slot
		String gaveUp;
		int steps;

		Run(AddressSet region, AddressSet inside) {
			this.region = region;
			this.inside = inside;
		}

		boolean isInside(Address a) {
			return inside == null || inside.contains(a);
		}

		void go(Address start, St st) {
			ArrayDeque<Address> work = new ArrayDeque<>();
			at.put(start, st);
			work.add(start);
			while (!work.isEmpty() && gaveUp == null) {
				Address a = work.pop();
				St s = at.get(a);
				if (++steps > 5000) {
					gaveUp = "more than 5000 steps";
					return;
				}
				Instruction in = listing.getInstructionAt(a);
				if (in == null) {
					gaveUp = "no instruction at " + a;
					return;
				}
				for (Object[] e : step(in, s)) {
					String kind = (String) e[0];
					St ns = (St) e[2];
					if (kind.equals("ret")) {
						T t = (T) e[1];
						if (inside == null) {
							returns = returns == null ? ns : returns.join(ns, in.getAddress());
							continue;
						}
						if (!t.isConst() && t.op.equals("load") && stackSlot(t.a[0])) {
							callerReturn = callerReturn == null ? ns : callerReturn.join(ns, in.getAddress());
							callerSlot = t.a[0];
							continue;
						}
						if (!t.isConst()) {
							gaveUp = "`" + in + "` at " + in.getAddress() + " goes to " + t;
							return;
						}
						flow(ram.getAddress(t.k), ns, work);
					}
					else if (kind.equals("jmpind")) {
						T t = (T) e[1];
						if (t.isConst()) {
							flow(ram.getAddress(t.k), ns, work);
						}
						else if (in.getFlows().length > 0) {
							for (Address f : in.getFlows()) {
								flow(f, ns.copy(), work);
							}
						}
						else {
							gaveUp = "`" + in + "` at " + in.getAddress() + " jumps to " + t;
							return;
						}
					}
					else {
						flow((Address) e[1], ns, work);
					}
				}
			}
		}

		void flow(Address to, St s, ArrayDeque<Address> work) {
			if (!isInside(to)) {
				St old = exits.get(to);
				exits.put(to, old == null ? s : old.join(s, to));
				return;
			}
			St old = at.get(to);
			St n = old == null ? s : old.join(s, to);
			if (old != null && n.equals(old)) {
				return;
			}
			int v = visits.merge(to, 1, Integer::sum);
			if (v > 12) {
				gaveUp = "no fixed point at " + to;
				return;
			}
			at.put(to, n);
			work.push(to);
		}
	}

	private boolean isEntry(Address a) {
		Function f = currentProgram.getFunctionManager().getFunctionAt(a);
		return f != null;
	}

	/** An address on the entry stack: SP, or SP plus a constant. */
	private static boolean stackSlot(T a) {
		T b = a.op.equals("add") ? a.a[0] : a;
		return b.op.equals("sym") && b.k == SP_OFF;
	}

	/** Run one instruction's p-code: [kind, target, state] per way out. */
	private List<Object[]> step(Instruction in, St st) {
		List<Object[]> outs = new ArrayList<>();
		PcodeOp[] ops = in.getPcode();
		ArrayDeque<Object[]> paths = new ArrayDeque<>();
		paths.add(new Object[] { 0, st.copy(), new HashMap<Long, T>() });
		int forks = 0;
		while (!paths.isEmpty()) {
			Object[] p = paths.pop();
			int i = (Integer) p[0];
			St s = (St) p[1];
			@SuppressWarnings("unchecked")
			Map<Long, T> tmp = (Map<Long, T>) p[2];
			boolean done = false;
			while (i < ops.length && !done) {
				PcodeOp op = ops[i];
				int oc = op.getOpcode();
				switch (oc) {
					case PcodeOp.BRANCH -> {
						Varnode d = op.getInput(0);
						if (d.isConstant()) {
							i += (int) d.getOffset();
						}
						else {
							outs.add(new Object[] { "jmp", d.getAddress(), s });
							done = true;
						}
					}
					case PcodeOp.CBRANCH -> {
						T c = val(op.getInput(1), s, tmp);
						Varnode d = op.getInput(0);
						boolean known = c.isConst();
						boolean take = known && c.k != 0;
						if (!known && forks++ < 32) {
							St other = s.copy();
							Map<Long, T> ot = new HashMap<>(tmp);
							if (d.isConstant()) {
								paths.add(new Object[] { i + (int) d.getOffset(), other, ot });
							}
							else {
								outs.add(new Object[] { "jmp", d.getAddress(), other });
							}
							i++;
						}
						else if (take || !known) {
							if (d.isConstant()) {
								i += (int) d.getOffset();
							}
							else {
								outs.add(new Object[] { "jmp", d.getAddress(), s });
								done = true;
							}
						}
						else {
							i++;
						}
					}
					case PcodeOp.BRANCHIND -> {
						outs.add(new Object[] { "jmpind", val(op.getInput(0), s, tmp), s });
						done = true;
					}
					case PcodeOp.RETURN -> {
						outs.add(new Object[] { "ret", val(op.getInput(0), s, tmp), s });
						done = true;
					}
					case PcodeOp.CALL, PcodeOp.CALLIND -> {
						Address callee = oc == PcodeOp.CALL ? op.getInput(0).getAddress() : null;
						if (callee == null) {
							T t = val(op.getInput(0), s, tmp);
							callee = t.isConst() ? ram.getAddress(t.k) : null;
						}
						call(callee, s);
						i++;
					}
					default -> {
						exec(op, s, tmp);
						i++;
					}
				}
			}
			if (!done) {
				Address ft = in.getFallThrough();
				if (ft != null) {
					outs.add(new Object[] { "jmp", ft, s });
				}
			}
		}
		return outs;
	}

	/** Apply a callee's summary at a call (after the return address is pushed). */
	private void call(Address callee, St s) {
		Summary sum = callee != null ? summarize(callee) : null;
		if (sum == null) {
			sum = new Summary();
			sum.clobbered.or(scratch);
		}
		long key = callee != null ? callee.getOffset() : -1;
		int n = s.calls.merge(key, 1, Integer::sum);
		for (int off = sum.clobbered.nextSetBit(0); off >= 0; off = sum.clobbered.nextSetBit(off + 1)) {
			s.regs.put(off, new T("call", key, 1, T.cnst(off, 2), T.cnst(n, 2)));
		}
		T sp = s.read(SP_OFF, 4);
		s.write(SP_OFF, 4, T.add(sp, sum.spDelta, 4));
		// The callee may write below its entry SP, and to its caller's frame
		// through pointers: drop what the stack held below the new SP.
		T nsp = s.read(SP_OFF, 4);
		s.mem.keySet().removeIf(k -> below(k, nsp));
	}

	private static boolean below(T addr, T sp) {
		T ab = addr.op.equals("add") ? addr.a[0] : addr, sb = sp.op.equals("add") ? sp.a[0] : sp;
		if (!ab.equals(sb)) {
			return false;
		}
		long ao = addr.op.equals("add") ? (addr.a[1].k << 32) >> 32 : 0;
		long so = sp.op.equals("add") ? (sp.a[1].k << 32) >> 32 : 0;
		return ao < so;
	}

	private T val(Varnode v, St s, Map<Long, T> tmp) {
		if (v.isConstant()) {
			return T.cnst(v.getOffset(), v.getSize());
		}
		if (v.isRegister()) {
			return s.read((int) v.getOffset(), v.getSize());
		}
		if (v.isUnique()) {
			T t = tmp.get(v.getOffset());
			return t != null ? t : new T("undef", v.getOffset(), v.getSize());
		}
		if (v.isAddress()) {
			return s.load(T.cnst(v.getOffset(), 4), v.getSize());
		}
		return new T("?", 0, v.getSize());
	}

	private void put(Varnode o, T v, St s, Map<Long, T> tmp) {
		if (o == null) {
			return;
		}
		if (o.isRegister()) {
			s.write((int) o.getOffset(), o.getSize(), v);
		}
		else if (o.isUnique()) {
			tmp.put(o.getOffset(), v);
		}
		else if (o.isAddress()) {
			s.store(T.cnst(o.getOffset(), 4), v);
		}
	}

	private void exec(PcodeOp op, St s, Map<Long, T> tmp) {
		Varnode o = op.getOutput();
		int oc = op.getOpcode();
		int size = o != null ? o.getSize() : 0;
		switch (oc) {
			case PcodeOp.COPY -> put(o, val(op.getInput(0), s, tmp), s, tmp);
			case PcodeOp.LOAD -> put(o, s.load(val(op.getInput(1), s, tmp), size), s, tmp);
			case PcodeOp.STORE -> s.store(val(op.getInput(1), s, tmp), val(op.getInput(2), s, tmp));
			case PcodeOp.INT_ADD -> {
				T x = val(op.getInput(0), s, tmp), y = val(op.getInput(1), s, tmp);
				put(o, y.isConst() ? T.add(x, y.k, size) : x.isConst() ? T.add(y, x.k, size)
						: new T("INT_ADD", 0, size, x, y), s, tmp);
			}
			case PcodeOp.INT_SUB -> {
				T x = val(op.getInput(0), s, tmp), y = val(op.getInput(1), s, tmp);
				put(o, y.isConst() ? T.add(x, -y.k, size) : new T("INT_SUB", 0, size, x, y), s, tmp);
			}
			default -> {
				T[] in = new T[op.getNumInputs()];
				boolean consts = true;
				for (int i = 0; i < in.length; i++) {
					in[i] = val(op.getInput(i), s, tmp);
					consts &= in[i].isConst();
				}
				T r = consts ? fold(oc, in, size) : null;
				put(o, r != null ? r : new T(PcodeOp.getMnemonic(oc), 0, size, in), s, tmp);
			}
		}
	}

	private static T fold(int oc, T[] in, int size) {
		long x = in.length > 0 ? in[0].k : 0, y = in.length > 1 ? in[1].k : 0;
		int xs = in.length > 0 ? in[0].size : 0;
		long sx = xs > 0 && xs < 8 ? (x << (64 - 8 * xs)) >> (64 - 8 * xs) : x;
		long sy = in.length > 1 && in[1].size < 8 ? (y << (64 - 8 * in[1].size)) >> (64 - 8 * in[1].size) : y;
		Long r = switch (oc) {
			case PcodeOp.INT_AND -> x & y;
			case PcodeOp.INT_OR -> x | y;
			case PcodeOp.INT_XOR -> x ^ y;
			case PcodeOp.INT_MULT -> x * y;
			case PcodeOp.INT_LEFT -> y >= 64 ? 0 : x << y;
			case PcodeOp.INT_RIGHT -> y >= 64 ? 0 : x >>> y;
			case PcodeOp.INT_SRIGHT -> y >= 64 ? (sx < 0 ? -1 : 0) : sx >> y;
			case PcodeOp.INT_NEGATE -> ~x;
			case PcodeOp.INT_2COMP -> -x;
			case PcodeOp.INT_ZEXT -> x;
			case PcodeOp.INT_SEXT -> sx;
			case PcodeOp.INT_EQUAL -> x == y ? 1L : 0L;
			case PcodeOp.INT_NOTEQUAL -> x != y ? 1L : 0L;
			case PcodeOp.INT_LESS -> Long.compareUnsigned(x, y) < 0 ? 1L : 0L;
			case PcodeOp.INT_LESSEQUAL -> Long.compareUnsigned(x, y) <= 0 ? 1L : 0L;
			case PcodeOp.INT_SLESS -> sx < sy ? 1L : 0L;
			case PcodeOp.INT_SLESSEQUAL -> sx <= sy ? 1L : 0L;
			case PcodeOp.BOOL_NEGATE -> x == 0 ? 1L : 0L;
			case PcodeOp.BOOL_AND -> (x != 0 && y != 0) ? 1L : 0L;
			case PcodeOp.BOOL_OR -> (x != 0 || y != 0) ? 1L : 0L;
			case PcodeOp.BOOL_XOR -> ((x != 0) ^ (y != 0)) ? 1L : 0L;
			case PcodeOp.SUBPIECE -> y >= 8 ? 0 : x >>> (8 * y);
			case PcodeOp.PIECE -> (x << (8 * in[1].size)) | y;
			default -> null;
		};
		return r == null ? null : T.cnst(r, size);
	}

	// ---- output -----------------------------------------------------------

	private void note(String text) {
		out.println("note\t" + text.replace('\t', ' ').replace('\n', ' '));
	}

	private void finding(String check, Address a, String text) {
		finding(check, a, text, List.of());
	}

	/** `regs`: the registers the finding is about (a waiver may name them). */
	private void finding(String check, Address a, String text, List<String> regs) {
		findings++;
		out.println("finding\t" + check + "\t" + a + "\t" + text.replace('\t', ' ').replace('\n', ' ') +
			"\t" + String.join(" ", regs));
		if (debug) {
			println("OtLintCf> " + check + " " + a + ": " + text);
		}
	}
}
