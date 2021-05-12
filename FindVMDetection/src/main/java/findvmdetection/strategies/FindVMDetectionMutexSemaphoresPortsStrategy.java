package findvmdetection.strategies;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionMutexSemaphoresPortsStrategy extends FindVMDetectionAnalyzingStrategyAbstract {
	
	private final Listing listing;
	private InstructionIterator instructions;
	private Instruction currentInstruction;
	private int suspiciousOccurrencesFound = 0;
	private Address [] jumpTargets;
	private List<Address> addressesOfOccurences = new ArrayList<>();
	private static final String IN_MNEMONIC = "IN";
	private static final String MOV_MNEMONIC = "MOV";
	private final static int MAX_DISTANCE_FOR_LITERAL_SET = 10; //Searches this many Instructions before after a Port reading instruction is found
	
	private final Long VM_WARE_PORT = 0x5658L; // 'VX'
	private final Long VM_WARE_MAGIC_VALUE = 0x564D5868L; // 'VMXh'
	
	
	
	public FindVMDetectionMutexSemaphoresPortsStrategy(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log, String strategyName) {
		super(program, set, monitor, log, strategyName);
		listing = program.getListing();
		instructions = listing.getInstructions(set, true);
	}



	public boolean step() {
		if(!instructions.hasNext()) {
			return false;
		}	
		currentInstruction = instructions.next();
		if(readsVMWarePort(currentInstruction)) {
			suspiciousOccurrencesFound++;
			
			addressesOfOccurences.add(currentInstruction.getAddress());
			currentInstruction.setComment(EOL_COMMENT, "Reads from VMWare Port 'VX'");
			
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



	private boolean readsVMWarePort(Instruction inst) {
		Register firstOperand;
		Register secondOperand;
		if(inst.getMnemonicString().compareToIgnoreCase(IN_MNEMONIC) == 0) {
			firstOperand = inst.getRegister(0);
			secondOperand = inst.getRegister(1);
			if(firstOperand == null || secondOperand == null) {
				return false;
			}
			if(hasBeenSetLiteral(firstOperand, VM_WARE_MAGIC_VALUE,inst) && hasBeenSetLiteral(secondOperand, VM_WARE_PORT, inst)) {
				return true;
			}
		}
		return false;
	}



	private boolean hasBeenSetLiteral(Register register, Long value, Instruction currentInst) {
		Instruction here = currentInst;
		Scalar moveValue;
		Register moveTarget;
		for(int i = 0; i < MAX_DISTANCE_FOR_LITERAL_SET; i++) {
			here = here.getPrevious();
			if(here.getMnemonicString().compareToIgnoreCase(MOV_MNEMONIC) == 0) {
				moveTarget = here.getRegister(0);
				moveValue = here.getScalar(1);
				if(moveTarget != null && moveTarget.contains(register)) {
					if(moveValue != null && moveValue.getValue() == value) {
						return true;
					}
					return false;
				}
			}
			
		}
		return false;
	}



	@Override
	public void init() throws CancelledException {
		super.init();
		// TODO Auto-generated method stub
		
	}



	@Override
	public void printResults() {
		printMessage("Found " + suspiciousOccurrencesFound + " suspicious Occurrences");
		if(!addressesOfOccurences.isEmpty()) {
			printMessage("First at: " + addressesOfOccurences.get(0).toString());
		}
	}

}
