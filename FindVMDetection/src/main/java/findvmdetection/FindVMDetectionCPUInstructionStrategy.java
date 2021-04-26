package findvmdetection;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionCPUInstructionStrategy extends FindVMDetectionAnalyzingStrategyAbstract{

	private final static int MAX_DISTANCE_FOR_JUMP = 1000; //Searches this many Instructions after a suspicious instruction is found
	private final static int EOL_COMMENT = 0; //Code for EOL-Comment
	
	private final Listing listing;
	private InstructionIterator instructions;
	private Instruction currentInstruction;
	private int suspiciousOccurrencesFound = 0;
	private Address [] jumpTargets;
	private List<Address> addressesOfOccurences = new ArrayList<>();
	
	private final List<String> suspiciousInstructions; 
	
	public FindVMDetectionCPUInstructionStrategy(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log, List<String> suspiciousInstructions){
		super(program, set, monitor, log);
		this.suspiciousInstructions = suspiciousInstructions;
		listing = program.getListing();
		instructions = listing.getInstructions(set, true);
	}

	/**
	 * one step of the analyzing process
	 * @return false to terminate analyzer
	 */
	public boolean step() {
		if(!instructions.hasNext()) {
			log.appendMsg("Found " + suspiciousOccurrencesFound + " suspicious Occurrences");
			if(!addressesOfOccurences.isEmpty()) {
				log.appendMsg("First at: " + addressesOfOccurences.get(0).toString());
			}
			return false;
		}
		currentInstruction = instructions.next();
		if(isSuspiciousInstruction(currentInstruction)) {
			suspiciousOccurrencesFound++;
			
			addressesOfOccurences.add(currentInstruction.getAddress());
			currentInstruction.setComment(0, "Might be used to distiguish between VM and Host");
			
			Instruction nextConditionalJump = seekToNextConditionalJump(currentInstruction);
			
			if(nextConditionalJump != null) {
				
				nextConditionalJump.setComment(EOL_COMMENT, "Might be the conditional jump determining VM behaviour");
				jumpTargets = nextConditionalJump.getFlows();
				
				for(Address target : jumpTargets) {
					listing.setComment(target, EOL_COMMENT, "Might be entry point for alternative VM behaviour");
				}
				nextConditionalJump.getNext().setComment(EOL_COMMENT, "Might be entry point for alternative VM behaviour");
			}
		}
		return true;
	}
	
	/**
	 * checks if this Instruction is considered suspicious
	 * @param inst the Instruction to be analyzed
	 * @return {@code true} if Instruction is suspicious
	 */
	private boolean isSuspiciousInstruction(Instruction inst) {
		return suspiciousInstructions.contains(inst.getMnemonicString());
	}
	
	/**
	 * 
	 * @param suspiciousInstrution the Instruction from where the next conditional jump is seeked, max is {@code MAX_DISTANCE_FOR_JUMP}
	 * @return the next conditional jump, null if  not found
	 */
	private Instruction seekToNextConditionalJump(Instruction suspiciousInstrution) {
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
}
