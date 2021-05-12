package findvmdetection.strategies;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionFilesDirectorysStrategy  extends FindVMDetectionAnalyzingStrategyAbstract {

	
	
	
	public FindVMDetectionFilesDirectorysStrategy(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName) {
		super(program, set, monitor, log, strategyName);
	}

	@Override
	public boolean step() {
		return super.step();
	}

	@Override
	public void init() throws CancelledException {
		super.init();
	}
}
