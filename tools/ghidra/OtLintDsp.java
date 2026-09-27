// Decode checks on a built DSP payload, against the stock payload the project
// holds.  analyzeHeadless -process -readOnly -noanalysis -postScript
// OtLintDsp.java DIR; for each program it reads DIR/PROGRAM.in and writes
// DIR/PROGRAM.out (a program with no .in is skipped).  ot_ghidra.py lint
// writes the inputs and reads the outputs.  Nothing is saved: the built words
// are written into the stock program for the length of this run only.
//
// Input (PROGRAM.in), one directive per line:
//   mem SPACE 0xWORD PATH      built words (3 bytes each, little-endian) from WORD on
//   loaded 0xWORD 0xCOUNT      P words the built payload's records load
//   xtab 0xINIT 0xPROC         the dispatch tables (X), 32 entries each
//
// Output, tab-separated, one fact per line:
//   form stock KEY ADDR        every stock instruction's form (the census)
//   form built KEY ADDR        every changed instruction's form
//   finding CHECK ADDR TEXT    do-loop-end | wild-target
//   note TEXT
//
// A form is the mnemonic and operands with numbers, addresses and the index
// of an address register replaced (r0-r3 and r4-r7 stay apart: dual moves
// care), plus the length in words.  ot_ghidra.py compares the built forms with
// both payloads' census.
//
// DEBUG set in the environment prints each finding as it is made.
//@category octabam
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;

public class OtLintDsp extends GhidraScript {

	private PrintWriter out;
	private boolean debug;
	private int findings;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			printerr("OtLintDsp: usage: OtLintDsp.java <dir holding PROGRAM.in>");
			return;
		}
		debug = System.getenv("DEBUG") != null && !System.getenv("DEBUG").isEmpty();
		File input = new File(args[0], currentProgram.getName() + ".in");
		if (!input.exists()) {
			println("OtLintDsp: " + currentProgram.getName() + ": no " + input.getName() + ", skipped");
			return;
		}
		out = new PrintWriter(new File(args[0], currentProgram.getName() + ".out"), "UTF-8");
		try {
			lint(input);
		}
		finally {
			out.close();
		}
		println(String.format("OtLintDsp: %s: %d findings", currentProgram.getName(), findings));
	}

	private void lint(File input) throws Exception {
		Listing listing = currentProgram.getListing();
		Memory mem = currentProgram.getMemory();
		AddressSpace P = currentProgram.getAddressFactory().getAddressSpace("P");
		AddressSpace X = currentProgram.getAddressFactory().getAddressSpace("X");
		AddressSet loaded = new AddressSet();
		List<String[]> mems = new ArrayList<>();
		long xinit = -1, xproc = -1;
		for (String line : Files.readAllLines(input.toPath())) {
			String[] f = line.trim().split("\\s+");
			if (f.length == 0 || f[0].isEmpty() || f[0].startsWith("#")) {
				continue;
			}
			switch (f[0]) {
				case "mem" -> mems.add(new String[] { f[1], f[2],
					new File(input.getParentFile(), f[3]).getPath() });
				case "loaded" -> {
					long a = Long.decode(f[1]), n = Long.decode(f[2]);
					loaded.add(word(P, a), word(P, a + n - 1).add(2));
				}
				case "xtab" -> {
					xinit = Long.decode(f[1]);
					xproc = Long.decode(f[2]);
				}
				default -> throw new IllegalArgumentException("unknown directive: " + line);
			}
		}

		// The stock census and the stock DO loops, before anything changes.
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction in = it.next();
			if (in.getAddress().getAddressSpace() != P) {
				continue;
			}
			out.println("form\tstock\t" + formKey(in) + "\t" + form(in) + "\t" + in.getAddress());
			String bad = loopEndProblem(in, listing);
			if (bad != null) {
				out.println("note\tstock already breaks the loop-end rule at " + in.getAddress() +
					": " + bad);
			}
		}

		// Find the built words that differ.
		AddressSet changed = new AddressSet();
		List<Object[]> writes = new ArrayList<>();
		for (String[] m : mems) {
			AddressSpace sp = currentProgram.getAddressFactory().getAddressSpace(m[0]);
			long start = Long.decode(m[1]);
			byte[] b = Files.readAllBytes(new File(m[2]).toPath());
			for (int i = 0; i + 3 <= b.length; i += 3) {
				Address a = word(sp, start + i / 3);
				byte[] old = new byte[3];
				if (!mem.contains(a) || mem.getBytes(a, old) != 3) {
					continue;
				}
				if (old[0] != b[i] || old[1] != b[i + 1] || old[2] != b[i + 2]) {
					writes.add(new Object[] { a, new byte[] { b[i], b[i + 1], b[i + 2] } });
					if (sp == P) {
						changed.add(a, a.add(2));
					}
				}
			}
		}
		out.println("note\t" + changed.getNumAddresses() / 3 + " P words changed");

		// An unchanged stock DO whose loop ends in changed words: its loop-end
		// context is cleared below with the rest, so it is disassembled again.
		AddressSet redo = new AddressSet();
		it = listing.getInstructions(P.getMinAddress(), true);
		while (it.hasNext()) {
			Instruction in = it.next();
			if (in.getAddress().getAddressSpace() != P) {
				break;
			}
			Address la = loopEnd(in);
			if (la != null && changed.contains(la) &&
				!changed.intersects(in.getMinAddress(), in.getMaxAddress())) {
				redo.add(in.getAddress());
			}
		}

		// Clear the stock code and its disassembly context (a DO's loop-end
		// marks, a REP's repeat mark) over the changed words, then write them.
		Register ctx = currentProgram.getProgramContext().getBaseContextRegister();
		for (Object[] w : writes) {
			Address a = (Address) w[0];
			Instruction was = listing.getInstructionContaining(a);
			if (was != null) {
				listing.clearCodeUnits(was.getMinAddress(), was.getMaxAddress(), false);
			}
			else {
				listing.clearCodeUnits(a, a, false);
			}
		}
		for (AddressRange r : redo) {
			listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
		}
		for (AddressRange r : changed) {
			currentProgram.getProgramContext().remove(r.getMinAddress(), r.getMaxAddress(), ctx);
		}
		for (Object[] w : writes) {
			mem.setBytes((Address) w[0], (byte[]) w[1]);
		}
		disassemble(redo);

		// Disassemble the built code: from every dispatch entry, then from the
		// start of every changed run nothing reached.
		List<long[]> entries = new ArrayList<>();
		if (xinit >= 0) {
			for (int i = 0; i < 32; i++) {
				entries.add(new long[] { xinit + i, readWord(mem, word(X, xinit + i)) });
				entries.add(new long[] { xproc + i, readWord(mem, word(X, xproc + i)) });
			}
		}
		AddressSet seeds = new AddressSet();
		for (long[] e : entries) {
			seeds.add(word(P, e[1]));
		}
		disassemble(seeds);
		for (AddressRange r : changed) {
			if (listing.getInstructionContaining(r.getMinAddress()) == null) {
				disassemble(new AddressSet(r.getMinAddress()));
			}
		}

		// Dispatch entries: each must be an instruction start the payload loads.
		for (long[] e : entries) {
			Address t = word(P, e[1]);
			String why = targetProblem(t, loaded, listing);
			if (why != null) {
				finding("wild-target", word(X, e[0]),
					"dispatch entry X:0x" + Long.toHexString(e[0]) + " -> " + t + ": " + why);
			}
		}

		// Every instruction that touches a changed word.  A changed word no
		// flow reaches is data (a module's table, read with movem p:): counted.
		AddressSet seen = new AddressSet();
		long data = 0;
		for (AddressRange r : changed) {
			Address a = r.getMinAddress();
			while (a != null && a.compareTo(r.getMaxAddress()) <= 0) {
				Instruction in = listing.getInstructionContaining(a);
				if (in == null) {
					data++;
					a = a.add(2).next();
					continue;
				}
				if (!seen.contains(in.getAddress())) {
					seen.add(in.getAddress());
					checkChanged(in, loaded, listing);
				}
				a = in.getMaxAddress().next();
			}
		}
		out.println("note\t" + data + " changed P words no flow reaches (data)");

		// DO loops whose body or end holds a changed word, wherever the DO is.
		it = listing.getInstructions(P.getMinAddress(), true);
		while (it.hasNext()) {
			Instruction in = it.next();
			if (in.getAddress().getAddressSpace() != P) {
				break;
			}
			Address la = loopEnd(in);
			if (la == null || la.compareTo(in.getAddress()) <= 0) {
				continue;
			}
			if (!changed.intersects(in.getAddress(), la)) {
				continue;
			}
			String bad = loopEndProblem(in, listing);
			if (bad != null) {
				finding("do-loop-end", in.getAddress(), bad);
			}
		}
	}

	private void checkChanged(Instruction in, AddressSet loaded, Listing listing) {
		out.println("form\tbuilt\t" + formKey(in) + "\t" + form(in) + "\t" + in.getAddress());
		for (Address t : in.getFlows()) {
			String why = targetProblem(t, loaded, listing);
			if (why != null) {
				finding("wild-target", in.getAddress(), "`" + in + "` -> " + t + ": " + why);
			}
		}
	}

	private String targetProblem(Address t, AddressSet loaded, Listing listing) {
		if (!loaded.contains(t)) {
			return "no record of the payload loads that word";
		}
		Instruction at = listing.getInstructionAt(t);
		if (at == null) {
			Instruction c = listing.getInstructionContaining(t);
			return c == null ? "does not decode" : "inside the two-word `" + c + "` at " + c.getAddress();
		}
		return null;
	}

	/** Why the instruction at a DO's loop end is illegal there, or null. */
	private String loopEndProblem(Instruction dox, Listing listing) {
		Address la = loopEnd(dox);
		if (la == null || la.compareTo(dox.getAddress()) <= 0) {
			return null;
		}
		// LA is the loop's last word: a two-word instruction ends there.
		Instruction last = listing.getInstructionContaining(la);
		if (last == null) {
			return "loop end " + la + " does not decode";
		}
		if (last.getMaxAddress().getAddressableWordOffset() != la.getAddressableWordOffset()) {
			return "loop end " + la + " is not the last word of `" + last + "` at " + last.getAddress();
		}
		String m = last.getMnemonicString().toLowerCase();
		if (m.startsWith("do") || m.equals("enddo") || m.startsWith("brk") || m.startsWith("rep")) {
			return "`" + last + "` at the loop end " + la + " (loop control there is illegal)";
		}
		// The loop-back is attached to LA's p-code, so look past it: any other
		// change of flow at LA is illegal.
		for (PcodeOp op : last.getPcode()) {
			int oc = op.getOpcode();
			if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND || oc == PcodeOp.RETURN ||
				oc == PcodeOp.BRANCHIND) {
				return "`" + last + "` at the loop end " + la + " (a change of flow there is illegal)";
			}
		}
		if (last.getFlowType().isJump() && !isLoopBackOnly(last, dox)) {
			return "`" + last + "` at the loop end " + la + " (a change of flow there is illegal)";
		}
		return null;
	}

	/** True when every flow out of LA is the loop-back to the DO's body. */
	private boolean isLoopBackOnly(Instruction last, Instruction dox) {
		Address top = dox.getFallThrough();
		for (Address f : last.getFlows()) {
			if (top == null || !f.equals(top)) {
				return false;
			}
		}
		return true;
	}

	/** The loop-end word a DO or DOR sets (`la = lastword` in its p-code). */
	private Address loopEnd(Instruction in) {
		String m = in.getMnemonicString().toLowerCase();
		if (!(m.equals("do") || m.equals("dor"))) {
			return null;
		}
		Register la = currentProgram.getRegister("la");
		for (PcodeOp op : in.getPcode()) {
			Varnode o = op.getOutput();
			if (op.getOpcode() == PcodeOp.COPY && o != null && o.isRegister() &&
				o.getOffset() == la.getOffset() && op.getInput(0).isConstant()) {
				return in.getAddress().getNewAddress(op.getInput(0).getOffset() *
					in.getAddress().getAddressSpace().getAddressableUnitSize());
			}
		}
		return null;
	}

	/**
	 * The encoding class: the bits the decoder's constructors constrain, and
	 * their values.  Operand fields the constructors only read (which register,
	 * which displacement) are masked out, so `teq x0,b` and `teq y1,b` share a
	 * class while an X move and a Y move, or a one- and a two-word form, do not.
	 */
	private static String formKey(Instruction in) {
		if (in.getPrototype() instanceof SleighInstructionPrototype sp) {
			// The root only wraps the `instr` table (with the loop-top and REP
			// context around it); the key starts there.
			ConstructState root = sp.getRootState();
			for (int i = 0; root != null && i < root.getNumSubStates(); i++) {
				ConstructState sub = root.getSubState(i);
				if (sub != null && sub.getConstructor() != null &&
					sub.getConstructor().getParent() != null &&
					"instr".equals(sub.getConstructor().getParent().getName())) {
					root = sub;
					break;
				}
			}
			StringBuilder s = new StringBuilder();
			constructors(root, s, true);
			return s.toString();
		}
		try {
			byte[] m = in.getPrototype().getInstructionMask().getBytes();
			byte[] b = in.getBytes();
			StringBuilder s = new StringBuilder();
			for (int i = 0; i < m.length && i < b.length; i++) {
				s.append(String.format("%02x", b[i] & m[i] & 0xff));
			}
			s.append('/');
			for (byte x : m) {
				s.append(String.format("%02x", x & 0xff));
			}
			return s.toString();
		}
		catch (Exception e) {
			return "?" + in.getMnemonicString();
		}
	}

	/**
	 * The SLEIGH constructors that decoded the instruction, by line: the root
	 * and every subtable constructor with operands of its own (an addressing
	 * mode, a parallel-move class).  A constructor with none only picks a
	 * register, so it counts by its table's name alone.
	 */
	private static void constructors(ConstructState st, StringBuilder s, boolean top) {
		if (st == null || st.getConstructor() == null) {
			return;
		}
		Constructor c = st.getConstructor();
		String table = c.getParent() == null ? "?" : c.getParent().getName();
		if (top || c.getNumOperands() > 0) {
			s.append(table).append(':').append(c.getLineno());
		}
		else {
			s.append(table);
		}
		if (st.getNumSubStates() > 0) {
			s.append('(');
			for (int i = 0; i < st.getNumSubStates(); i++) {
				if (i > 0) {
					s.append(',');
				}
				constructors(st.getSubState(i), s, false);
			}
			s.append(')');
		}
	}

	private String form(Instruction in) {
		StringBuilder s = new StringBuilder(in.getMnemonicString().toLowerCase());
		for (int i = 0; i < in.getNumOperands(); i++) {
			s.append(i == 0 ? " " : ",");
			List<Object> parts = in.getDefaultOperandRepresentationList(i);
			if (parts == null) {
				s.append("?");
				continue;
			}
			for (Object p : parts) {
				if (p instanceof Register r) {
					s.append(reg(r.getName().toLowerCase()));
				}
				else if (p instanceof Scalar) {
					s.append('#');
				}
				else if (p instanceof Address) {
					s.append('@');
				}
				else {
					s.append(p.toString().toLowerCase().replaceAll("0x[0-9a-f]+|\\$[0-9a-f]+|[0-9]+", "#"));
				}
			}
		}
		s.append(" /").append(in.getLength() / 3);
		return s.toString();
	}

	private static String reg(String r) {
		if (r.matches("r[0-3]")) {
			return "r03";
		}
		if (r.matches("r[4-7]")) {
			return "r47";
		}
		if (r.matches("[nm][0-7]")) {
			return r.substring(0, 1);
		}
		return r;
	}

	private void finding(String check, Address a, String text) {
		findings++;
		out.println("finding\t" + check + "\t" + a + "\t" + text.replace('\t', ' ').replace('\n', ' '));
		if (debug) {
			println("OtLintDsp> " + check + " " + a + ": " + text);
		}
	}

	private void disassemble(AddressSet seeds) {
		DisassembleCommand cmd = new DisassembleCommand(seeds, null, true);
		cmd.applyTo(currentProgram, monitor);
	}

	private static Address word(AddressSpace sp, long w) {
		return sp.getTruncatedAddress(w, true);
	}

	private static long readWord(Memory mem, Address a) throws Exception {
		byte[] b = new byte[3];
		mem.getBytes(a, b);
		return (b[0] & 0xff) | (b[1] & 0xff) << 8 | (b[2] & 0xff) << 16;
	}
}
