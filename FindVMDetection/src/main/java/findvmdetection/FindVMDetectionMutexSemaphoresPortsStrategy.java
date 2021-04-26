package findvmdetection;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionMutexSemaphoresPortsStrategy extends FindVMDetectionAnalyzingStrategyAbstract {
	private final static int EOL_COMMENT = 0; //Code for EOL-Comment
	
	private final Listing listing;
	private InstructionIterator instructions;
	private Instruction currentInstruction;
	
	private final int VM_WARE_PORT = 0x5658;
	
	
	
	public FindVMDetectionMutexSemaphoresPortsStrategy(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		super(program, set, monitor, log);
		listing = program.getListing();
		instructions = listing.getInstructions(set, true);
	}



	public boolean step() {
		// TODO Auto-generated method stub
		return false;
	}

}
