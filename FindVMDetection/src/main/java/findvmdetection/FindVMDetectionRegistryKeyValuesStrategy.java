package findvmdetection;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionRegistryKeyValuesStrategy  extends FindVMDetectionAnalyzingStrategyAbstract  {

	public FindVMDetectionRegistryKeyValuesStrategy(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		super(program, set, monitor, log);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean step() {
		// TODO Auto-generated method stub
		return false;
	}

}
