package findvmdetection.strategies;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionLoadedDriversDevicesStrategy extends FindVMDetectionAnalyzingStrategyAbstract {

	public FindVMDetectionLoadedDriversDevicesStrategy(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName) {
		super(program, set, monitor, log, strategyName);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean step() {
		return false;
	}

	@Override
	public void init() throws CancelledException {
		super.init();
		
	}

	@Override
	public void printResults() {
		// TODO Auto-generated method stub
		
	}

}
