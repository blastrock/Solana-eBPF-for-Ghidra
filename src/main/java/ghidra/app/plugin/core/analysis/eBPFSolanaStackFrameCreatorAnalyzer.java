package ghidra.app.plugin.core.analysis;

import ghidra.app.plugin.core.function.editor.FunctionEditorModel;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;

public class eBPFSolanaStackFrameCreatorAnalyzer extends AbstractAnalyzer {

	private final static String PROCESSOR_NAME = "eBPFSol";
	private final static String NAME = "eBPF stack frame creator";
	private final static String DESCRIPTION =
			"Injects pcode stack frame prologue/epilogue into functions";

	private long lastTransactionId = -1;

	public eBPFSolanaStackFrameCreatorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// only perform this analysis once per transaction
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTransactionId) {
			return true;
		}
		lastTransactionId = txId;

		//PcodeInjectLibrary snippetLibrary = program.getCompilerSpec().getPcodeInjectLibrary();
		//snippetLibrary.

		return true;
	}
}
