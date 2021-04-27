package findvmdetection;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public abstract class FindVMDetectionAnalyzingStrategyAbstract {

	private final static int MAX_DISTANCE_FOR_JUMP = 1000; //Searches this many Instructions after a suspicious instruction is found
	protected final Program program;
	protected final AddressSetView set;
	protected final TaskMonitor monitor;
	protected final MessageLog log;
	protected final String strategyName;
	
	protected final static int EOL_COMMENT = 0; //Code for EOL-Comment
	
	
	public FindVMDetectionAnalyzingStrategyAbstract(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName) {
		this.program = program;
		this.set = set;
		this.monitor = monitor;
		this.log = log;
		this.strategyName = strategyName;
	}


	/**
	 * Atomic step of the Analyzing Strategy, Analyzing process may be cancelled in between steps
	 * @return false to terminate this strategy
	 */
	public abstract boolean step();
	
	/**
	 * Init function called after constructor
	 */
	public abstract void init() throws CancelledException;
	
	/**
	 * 
	 * @param suspiciousInstrution the Instruction from where the next conditional jump is seeked, max is {@code MAX_DISTANCE_FOR_JUMP}
	 * @return the next conditional jump, null if  not found
	 */
	protected Instruction seekToNextConditionalJump(Instruction suspiciousInstrution) {
		int currentDistance = 0;
		Instruction inst = suspiciousInstrution;
		
		while(inst.isFallthrough() && currentDistance < MAX_DISTANCE_FOR_JUMP) {
			inst= inst.getNext();
		}
		
		if(currentDistance != MAX_DISTANCE_FOR_JUMP) {
			return inst;
		}
		
		return null;
	}
	
	/**
	 * prints a message with a preceding strategy unique description using the provided MessageLog object
	 * @param msg the String to be printed
	 */
	protected void printMessage(String msg) {
		log.appendMsg(strategyName + ": " + msg);
	}
	
	
}
