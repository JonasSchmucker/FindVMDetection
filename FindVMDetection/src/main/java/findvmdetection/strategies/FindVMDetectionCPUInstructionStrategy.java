package findvmdetection.strategies;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;

import findvmdetection.util.FindVMDetectionBookmarks;
import findvmdetection.util.FindVMDetectionCSVLoader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


public class FindVMDetectionCPUInstructionStrategy extends FindVMDetectionAnalyzingStrategyAbstract{
	
	private final Listing listing;
	private InstructionIterator instructions;
	private File csvFile;
	private boolean jsonAnalysisRunning = true;
	
	private List<String> suspiciousInstructions; 
	
	public FindVMDetectionCPUInstructionStrategy(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log, String strategyName, FindVMDetectionBookmarks bookmarks){
		super(program, set, monitor, log, strategyName, bookmarks);
		listing = program.getListing();
		instructions = listing.getInstructions(set, true);

		csvFile = Paths.get(System.getProperty("user.dir"))
					.resolve("src").resolve("main").resolve("resources").resolve("suspiciousMnemonics.csv")
					.toFile();
	}

	/**
	 * one step of the analyzing process
	 * @return false to terminate this strategy
	 */
	public boolean step() {
		if(jsonAnalysisRunning) {
			jsonAnalysisRunning &= super.step();
			return true;
		}
		if(!instructions.hasNext()) {
			return false;
		}
		currentInstruction = instructions.next();
		if(isSuspiciousInstruction(currentInstruction)) {
			bookmarks.setBookmark(currentInstruction.getAddress(), this);
			
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

	public void init() throws CancelledException {
		super.init();
		FindVMDetectionCSVLoader csvLoader = new FindVMDetectionCSVLoader(csvFile);
		
		
		try {
			suspiciousInstructions = csvLoader.getSuspiciousInstructions();
		}
		catch(IOException e) {
			log.appendMsg("Error while loading " + csvFile.getAbsolutePath());
			throw new CancelledException("Error while loading " + csvFile.getAbsolutePath());
		}
		
		if(suspiciousInstructions.isEmpty()) {
			log.appendMsg("Empyty .csv File at " + csvFile.getAbsolutePath());
			throw new CancelledException("Empyty .csv File at " + csvFile.getAbsolutePath());
		}
		
	}
}
