package findvmdetection;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public abstract class FindVMDetectionAnalyzingStrategyAbstract {
	protected final Program program;
	protected final AddressSetView set;
	protected final TaskMonitor monitor;
	protected final MessageLog log;
	
	
	public FindVMDetectionAnalyzingStrategyAbstract(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		this.program = program;
		this.set = set;
		this.monitor = monitor;
		this.log = log;
	}


	/**
	 * Atomic step of the Analyzing Strategy, Analyzing process may be cancelled in between steps
	 * @return false to terminate this strategy
	 */
	public abstract boolean step();
}
