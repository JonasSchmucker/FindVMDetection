package findvmdetection.strategies;

import findvmdetection.util.FindVMDetectionBookmarks;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionRunningProcessesStrategy extends FindVMDetectionAnalyzingStrategyAbstract {

	public FindVMDetectionRunningProcessesStrategy(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName, FindVMDetectionBookmarks bookmarks) {
		super(program, set, monitor, log, strategyName, bookmarks);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean step() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void init() throws CancelledException {
		super.init();
		// TODO Auto-generated method stub
		
	}

	@Override
	public void printResults() {
		// TODO Auto-generated method stub
		
	}

}
