package findvmdetection.strategies;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import findvmdetection.util.FindVMDetectionConstantUseFinder;
import findvmdetection.util.FindVMDetectionRulesData;
import generic.json.JSONError;
import generic.json.JSONParser;
import generic.json.JSONToken;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.OperatingSystem;
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
	public final Program program;
	protected final AddressSetView set;
	public final TaskMonitor monitor;
	protected final MessageLog log;
	protected final String strategyName;
	static final FindVMDetectionConstantUseFinder constantUseFinder = new FindVMDetectionConstantUseFinder();
	protected FindVMDetectionRulesData rules;
	static OperatingSystem os;
	File jsonRuleFile;
	
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
	public void init() throws CancelledException{
		loadRules();
	}
	
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
	public void printMessage(String msg) {
		log.appendMsg(strategyName + ": " + msg);
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
				printMessage("ERROR with OS");
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
			printMessage(ex.getMessage());
			throw ex;
		} catch (IOException e) {
			CancelledException ex = new CancelledException("ERROR reading File");
			printMessage(ex.getMessage());
			throw ex;
		}
		finally {
		    try {
				br.close();
			} catch (IOException e) {
				CancelledException ex = new CancelledException("ERROR closing File");
				printMessage(ex.getMessage());
				throw ex;
			}
		    catch (NullPointerException e) {
				CancelledException ex = new CancelledException("ERROR closing File");
				printMessage(ex.getMessage());
				throw ex;
		    }
		}
		
		JSONError er = parser.parse(jsonContent, tokens);
		if(er != JSONError.JSMN_SUCCESS) {
			printMessage(er.toString());
		}
		Object obj = parser.convert(jsonContent, tokens);
		rules = new FindVMDetectionRulesData();
		try {
			rules.populate(obj);
		}
		catch(Exception e) {
			printMessage("ERROR in json File Syntax");
			throw e;
		}
	}


	public static void setOs(OperatingSystem os) {
		FindVMDetectionAnalyzingStrategyAbstract.os = os;
	} 
	
	public abstract void printResults();
	
	
}
