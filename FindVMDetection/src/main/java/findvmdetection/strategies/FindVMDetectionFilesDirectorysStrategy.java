package findvmdetection.strategies;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import findvmdetection.ruleJsonData.DLLRulesData;
import findvmdetection.ruleJsonData.FunctionRulesData;
import findvmdetection.ruleJsonData.ParameterRulesData;
import findvmdetection.util.FindVMDetectionConstantUseFinder;
import findvmdetection.util.FindVMDetectionConstantUseFinder.ConstUseLocation;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionFilesDirectorysStrategy  extends FindVMDetectionAnalyzingStrategyAbstract {

	private Function currentFunction;
	private ExternalManager externalManager;
	private ExternalLocationIterator extLocIter;
	
	
	Iterator<DLLRulesData> dllRuleIterator;
	DLLRulesData currentDLLRule;
	private Instruction currentInstruction;
	private int suspiciousOccurrencesFound = 0;
	private Address [] jumpTargets;
	private List<Address> addressesOfOccurences = new ArrayList<>();
	
	public FindVMDetectionFilesDirectorysStrategy(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName) {
		super(program, set, monitor, log, strategyName);
		externalManager = program.getExternalManager();
	}

	@Override
	public boolean step() {
		constantUseFinder.reset();
		constantUseFinder.signInStrategy(this);
		constantUseFinder.initialiseDecompiler();
		if(dllRuleIterator.hasNext()) {
			currentDLLRule = dllRuleIterator.next();
			if(!usesKernerExternalLibrary(currentDLLRule.dllName)) {
				return true;
			}
			extLocIter = externalManager.getExternalLocations(currentDLLRule.dllName);
			for(ExternalLocation currentExtLoc : getIterableFromIterator(extLocIter)){
				if(monitor.isCancelled()) {
					return false;
				}
				if(!currentExtLoc.isFunction()) {
					continue;
				}
				
				currentFunction = currentExtLoc.getFunction();
				for(FunctionRulesData currentFunctionRule : currentDLLRule.functions) {
					if(monitor.isCancelled()) {
						return false;
					}
					if(currentFunction.getName().compareToIgnoreCase(currentFunctionRule.functionName) == 0) {
						for(ParameterRulesData currentParameterRule : currentFunctionRule.parameters) {
							Address suspectedVMDetectionAddress = checkAgainstRules(currentFunction, currentParameterRule);
							if(suspectedVMDetectionAddress  != null) {
								suspiciousOccurrencesFound++;
								
								addressesOfOccurences.add(suspectedVMDetectionAddress);
								currentInstruction = program.getListing().getInstructionAt(suspectedVMDetectionAddress);
								currentInstruction.setComment(EOL_COMMENT, "Might be used to distiguish between VM and Host");
								
								Instruction nextConditionalJump = seekToNextConditionalJump(currentInstruction);
								
								if(nextConditionalJump != null) {
									
									nextConditionalJump.setComment(EOL_COMMENT, "Might be the conditional jump determining VM behaviour");
									jumpTargets = nextConditionalJump.getFlows();
									
									for(Address target : jumpTargets) {
										program.getListing().setComment(target, EOL_COMMENT, "Might be entry point for alternative VM behaviour");
									}
									nextConditionalJump.getNext().setComment(EOL_COMMENT, "Might be entry point for alternative VM behaviour");
								}
							}
						}
					}
				}
			}
			return true;
		}
		return false;
	}

	@Override
	public void init() throws CancelledException {
		super.init();
		dllRuleIterator = rules.dlls.iterator();
	}
	
	public boolean usesKernerExternalLibrary(String name) {
		return externalManager.getExternalLibrary(name) != null;
	}
	
	public static <T> Iterable<T> getIterableFromIterator(Iterator<T> iterator)
    {
        return new Iterable<T>() {
            @Override
            public Iterator<T> iterator()
            {
                return iterator;
            }
        };
    }

	private Address checkAgainstRules(Function f, ParameterRulesData paramRule) {
		constantUseFinder.reset();
		constantUseFinder.signInStrategy(this);
		constantUseFinder.initialiseDecompiler();
		if(paramRule.paramType.compareToIgnoreCase("stringPointer") == 0) {
			return checkAgainstStringRules(f, paramRule);
		}
		else if(paramRule.paramType.compareToIgnoreCase("integer") == 0) {
			return checkAgainstIntegerRules(f, paramRule);
		}
		else {
			printMessage("ERROR in file");
		}
		return null;
	}

	private Address checkAgainstStringRules(Function f, ParameterRulesData paramRule) {
		try {
			constantUseFinder.backtrackParamToConstant(currentFunction, paramRule.paramOrdinal);
		}
		catch(CancelledException e) {
			return null;
		}
		
		for(ConstUseLocation constLoc : constantUseFinder.constUses) {
			String constString = getStringFromConstUseLocation(constLoc);
			if(constString != null) {
				if( isForbiddenStringsInConstant(paramRule, constString)) {
					return constLoc.getAddress();
				}
			}
		}
		return null;
	}

	private boolean isForbiddenStringsInConstant(ParameterRulesData paramRule, String constantString) {
		if(paramRule.forbiddenValue.contains(constantString) || constantString.contains(paramRule.forbiddenValue)) { 
			return true;
		}
		return false;
	}

	private Address checkAgainstIntegerRules(Function f, ParameterRulesData paramRule) {
		// TODO Auto-generated method stub
		return null;
	}
	
	private String getStringFromConstUseLocation(ConstUseLocation constLoc) {
		if(constLoc.getConstValue() != null && constLoc.getAddress() != null) {
			return program.getListing()
						.getDataAt(
								constLoc.getAddress().getNewAddress(
										constLoc.getConstValue()
								)
						).getDefaultValueRepresentation();
		}
		return null;
	}

	@Override
	public void printResults() {
		printMessage("Found " + suspiciousOccurrencesFound + " suspicious Occurrences");
		if(!addressesOfOccurences.isEmpty()) {
			printMessage("First at: " + addressesOfOccurences.get(0).toString());
		}
	}
}
