package findvmdetection.strategies;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import findvmdetection.ruleJsonData.DLLRulesData;
import findvmdetection.ruleJsonData.FunctionRulesData;
import findvmdetection.ruleJsonData.ParameterRulesData;
import findvmdetection.util.FindVMDetectionBookmarks;
import findvmdetection.util.FindVMDetectionConstantUseFinder;
import findvmdetection.util.FindVMDetectionRulesData;
import findvmdetection.util.FindVMDetectionConstantUseFinder.ConstUseLocation;
import generic.json.JSONError;
import generic.json.JSONParser;
import generic.json.JSONToken;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.OperatingSystem;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * @author Jonas Schmucker
 *
 */
public abstract class FindVMDetectionAnalyzingStrategyAbstract {

	private final static int MAX_DISTANCE_FOR_JUMP = 1000; //Searches this many Instructions after a suspicious instruction is found
	public final Program program;
	protected final AddressSetView set;
	public final TaskMonitor monitor;
	protected final MessageLog log;
	public final String strategyName;
	protected final FindVMDetectionBookmarks bookmarks;
	static final FindVMDetectionConstantUseFinder constantUseFinder = new FindVMDetectionConstantUseFinder();
	protected FindVMDetectionRulesData rules;
	public boolean verbose;
	static OperatingSystem os;
	File jsonRuleFile;

	Function currentFunction;
	ExternalManager externalManager;
	ExternalLocationIterator extLocIter;
	

	Iterator<DLLRulesData> dllRuleIterator;
	DLLRulesData currentDLLRule;
	Instruction currentInstruction;
	Address [] jumpTargets;
	
	protected final static int EOL_COMMENT = 0; //Code for EOL-Comment
	
	
	public FindVMDetectionAnalyzingStrategyAbstract(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log, String strategyName, FindVMDetectionBookmarks bookmarks) {
		this.program = program;
		this.set = set;
		this.monitor = monitor;
		this.log = log;
		this.strategyName = strategyName;
		this.bookmarks = bookmarks;
	}


	/**
	 * Atomic step of the Analyzing Strategy, Analyzing process may be cancelled in between steps
	 * @return false to terminate this strategy
	 */
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
								bookmarks.setBookmark(suspectedVMDetectionAddress, this);
								currentInstruction = program.getListing().getInstructionAt(suspectedVMDetectionAddress);
								
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
	
	/**
	 * Init function called after constructor
	 */
	public void init() throws CancelledException{
		loadRules();
		dllRuleIterator = rules.dlls.iterator();
		externalManager = program.getExternalManager();
	}
	
	/**
	 * 
	 * @param suspiciousInstrution the Instruction from where the next conditional jump is seeked, max is {@code MAX_DISTANCE_FOR_JUMP}
	 * @return the next conditional jump, null if  not found
	 */
	protected Instruction seekToNextConditionalJump(Instruction suspiciousInstrution) {
		int currentDistance = 0;
		Instruction inst = suspiciousInstrution.getNext();
			
		
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
	 * @param errorMessage 
	 */
	public void printMessage(String msg, boolean errorMessage) {
		if(verbose || errorMessage) {
			log.appendMsg(strategyName + ": " + msg);
		}
	}
	
	public void loadRules() throws CancelledException{
		Path pathToJson = Paths.get(System.getProperty("user.dir"))
				.resolve("src").resolve("main").resolve("resources").resolve("SysCallRules");
		switch(os) {
			case LINUX:
				pathToJson = pathToJson.resolve("LINUX");
				break;
			case MAC_OS_X:
				pathToJson = pathToJson.resolve("MAC_OS_X");
				break;
			case WINDOWS:
				pathToJson = pathToJson.resolve("WINDOWS");
				break;
			default:
				printMessage("ERROR with OS", true);
				break;
		}
		String fileName = "";
		if("CPU Instruction Analysis".compareTo(strategyName) == 0) {
			fileName = "CPUInstructionStrategy.json";
		}
		else if("User and Computer Names Analysis".compareTo(strategyName) == 0) {
			fileName = "UserAndComputerNamesStrategy.json";
		}
		else if("Running Processes Analysis".compareTo(strategyName) == 0) {
			fileName = "RunningProcessesStrategy.json";
		}
		else if("Running Services Analysis".compareTo(strategyName) == 0) {
			fileName = "RunningServicesStrategy.json";
		}
		else if("Loaded Modules and Memory Analysis".compareTo(strategyName) == 0) {
			fileName = "LoadedModulesAndMemoryStrategy.json";
		}
		else if("Loaded Drivers and Devices Analysis".compareTo(strategyName) == 0) {
			fileName = "LoadedDriversAndDevicesStrategy.json";
		}
		else if("Files and Directorys Analysis".compareTo(strategyName) == 0) {
			fileName = "FilesAndDirectorysStrategy.json";
		}
		else if("Registry Keys Analysis".compareTo(strategyName) == 0) {
			fileName = "RegistryKeysStrategy.json";
		}
		else if("Mutex Semaphores and Ports Analysis".compareTo(strategyName) == 0) {
			fileName = "MutexSemaphoresAndPortsStrategy.json";
		}
		else {
			throw new CancelledException("ERROR finding File to load");
		}
		
		jsonRuleFile = pathToJson.resolve(fileName).toFile();
		
		JSONParser parser = new JSONParser();
		List<JSONToken> tokens = new ArrayList<>();
		BufferedReader br = null;
		char [] jsonContent;
		try {
			FileReader reader = new FileReader(jsonRuleFile);
		
			br = new BufferedReader(reader);
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		    }
		    jsonContent = new char[sb.length()];
		    sb.getChars(0, sb.length(), jsonContent, 0);
		} 
		catch (FileNotFoundException e) {
			CancelledException ex = new CancelledException("ERROR file not found: " + fileName);
			printMessage(ex.getMessage(), true);
			throw ex;
		} catch (IOException e) {
			CancelledException ex = new CancelledException("ERROR reading File");
			printMessage(ex.getMessage(), true);
			throw ex;
		}
		finally {
		    try {
				br.close();
			} catch (IOException e) {
				CancelledException ex = new CancelledException("ERROR closing File");
				printMessage(ex.getMessage(), true);
				throw ex;
			}
		    catch (NullPointerException e) {
				CancelledException ex = new CancelledException("ERROR closing File");
				printMessage(ex.getMessage(), true);
				throw ex;
		    }
		}
		
		JSONError er = parser.parse(jsonContent, tokens);
		if(er != JSONError.JSMN_SUCCESS) {
			printMessage(er.toString(), true);
		}
		Object obj = parser.convert(jsonContent, tokens);
		rules = new FindVMDetectionRulesData();
		try {
			rules.populate(obj);
		}
		catch(Exception e) {
			printMessage("ERROR in json File Syntax", true);
			throw e;
		}
	}


	public static void setOs(OperatingSystem os) {
		FindVMDetectionAnalyzingStrategyAbstract.os = os;
	} 
	
	public void printResults() {
		
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

	protected Address checkAgainstRules(Function f, ParameterRulesData paramRule) {
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
			printMessage("ERROR in file", true);
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
				if( isForbiddenStringInConstant(paramRule, constString)) {
					return constLoc.getAddress();
				}
			}
		}
		return null;
	}

	private boolean isForbiddenStringInConstant(ParameterRulesData paramRule, String constantString) {
		if(paramRule.forbiddenValue.contains(constantString) || constantString.contains(paramRule.forbiddenValue)) { 
			return true;
		}
		return false;
	}

	private Address checkAgainstIntegerRules(Function f, ParameterRulesData paramRule) {
		try {
			constantUseFinder.backtrackParamToConstant(currentFunction, paramRule.paramOrdinal);
		}
		catch(CancelledException e) {
			return null;
		}
		
		for(ConstUseLocation constLoc : constantUseFinder.constUses) {
			Integer constInt = getIntegerFromConstUseLocation(constLoc);
			if(constInt != null) {
				if( isForbiddenIntegerInConstant(paramRule, constInt)) {
					return constLoc.getAddress();
				}
			}
		}
		return null;
	}
	
	private Integer getIntegerFromConstUseLocation(ConstUseLocation constLoc) {
		if(constLoc.getConstValue() != null && constLoc.getAddress() != null) {
			return (Integer) program.getListing()
						.getDataAt(
								constLoc.getAddress().getNewAddress(constLoc.getConstValue())
						).getValue();
		}
		return null;
	}

	private boolean isForbiddenIntegerInConstant(ParameterRulesData paramRule, int constInt) {
		return Integer.parseInt(paramRule.forbiddenValue) == constInt;
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
	
	
}
