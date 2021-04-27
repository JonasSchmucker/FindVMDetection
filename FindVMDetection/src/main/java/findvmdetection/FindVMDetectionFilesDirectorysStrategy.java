package findvmdetection;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionFilesDirectorysStrategy  extends FindVMDetectionAnalyzingStrategyAbstract {

	private FunctionIterator functions;
	private FunctionManager functionManager;
	
	public FindVMDetectionFilesDirectorysStrategy(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName) {
		super(program, set, monitor, log, strategyName);
		functionManager = program.getFunctionManager();
	}

	@Override
	public boolean step() {
		Function currentFunction;
		if(!functions.hasNext()) {
			return false;
		}
		currentFunction = functions.next();
		printMessage(currentFunction.getName());
		return true;
	}

	@Override
	public void init() throws CancelledException {
		functions = functionManager.getFunctions(true);
	}

}
