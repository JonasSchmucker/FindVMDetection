/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Durchsucht das Dekompilierte Listing nach Maschinenbefehlen, die auf eine VM-Detektion hinweisen
//@author Jonas Schmucker, 19.04.2021
//@category bachelorarbeit.analyzer
//@keybinding 

package findvmdetection;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds where Malware might detected a VM, and shows alternative behaviours for Host and VM
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionAnalyzer extends AbstractAnalyzer {

	private static final String ANALYSER_SHORT_DESCRIPTION = "Finds where Malware might detected a VM, and shows alternative Behaviours for Host and VM";
	private static final String ANALYSER_NAME = "Find VM Detection";
	private static final String NO_STRATEGY_SELECTED = "No Strategy / Strategies selected";
	private static final String ANALYZER_WAS_CANCELLED_PER_USER_REQUEST = "Analyzer was cancelled per user request";
	private final static String OPTION_ONE_NAME = "Path to suspicious Mnemonics csv";
	private final static String HOVER_OPTION_ONE_TEXT = "Path to suspicious Mnemonics csv";
	private final static String DEFAULT_PATH_TO_CSV = "C:\\Users\\jonas\\git\\FindVMDetection\\FindVMDetection\\src\\main\\resources\\testMnemonic.csv";
	private final static File DEFAULT_CSV_FILE = new File(DEFAULT_PATH_TO_CSV);
	private final static int STRATEGY_COUNT = 9;
	private final static String [] STRATEGY_NAMES = {
			"CPU Instruction Analysis",
			"User and Computer Names Analysis",
			"Running Processes Analysis",
			"Running Services Analysis",
			"Loaded Modules and Memory Analysis",
			"Loaded Drivers and Devices Analysis",
			"Files and Directorys Analysis",
			"Registry Keys Analysis",
			"Mutex Semaphores and Ports Analysis"
		};
	
	
	private List<FindVMDetectionAnalyzingStrategyAbstract> queuedStrategies = new ArrayList<>();
	private boolean [] strategyToRun = new boolean [STRATEGY_COUNT];
	private File csvFile;

	public FindVMDetectionAnalyzer() {


		super(ANALYSER_NAME,
				ANALYSER_SHORT_DESCRIPTION,
				AnalyzerType.INSTRUCTION_ANALYZER
			);

		Arrays.fill(strategyToRun, true);
		strategyToRun[1] = false; // not yet implemented
		strategyToRun[2] = false; // not yet implemented
		strategyToRun[3] = false; // not yet implemented
		strategyToRun[4] = false; // not yet implemented
		strategyToRun[5] = false; // not yet implemented
		strategyToRun[6] = false; // not yet implemented
		strategyToRun[7] = false; // not yet implemented
	}
 
	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default
		

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		FindVMDetectionCSVLoader csvLoader = new FindVMDetectionCSVLoader(csvFile);
		
		List<String> suspiciousInstructions;
		
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
		
		populateStrategyQueue(program, set, monitor, log, suspiciousInstructions);
		
		if(queuedStrategies.isEmpty()) {
			CancelledException e = new CancelledException(NO_STRATEGY_SELECTED);
			throw e;
		}
		
		for(FindVMDetectionAnalyzingStrategyAbstract strategy : queuedStrategies) {
			if(monitor.isCancelled()) {
				CancelledException e = new CancelledException(ANALYZER_WAS_CANCELLED_PER_USER_REQUEST);
				throw e;
			}
			
			while(strategy.step() && !monitor.isCancelled()) {}
			
		}

		if(monitor.isCancelled()) {
			CancelledException e = new CancelledException(ANALYZER_WAS_CANCELLED_PER_USER_REQUEST);
			throw e;
		}
		
		return true; //Analysis should have succeeded if this is reached
	}

	@Override
	public void analysisEnded(Program program) {
		super.analysisEnded(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(
					OPTION_ONE_NAME, 
					OptionType.FILE_TYPE, 
					DEFAULT_CSV_FILE,
					null,
					HOVER_OPTION_ONE_TEXT
				);
		
		for(int i = 0; i < STRATEGY_COUNT; i++) {
			options.registerOption(
					STRATEGY_NAMES[i],
					OptionType.BOOLEAN_TYPE,
					strategyToRun[i],
					null,
					STRATEGY_NAMES[i]
				);
		}
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		csvFile = options.getFile(OPTION_ONE_NAME, DEFAULT_CSV_FILE);
		
		for(int i = 0; i < STRATEGY_COUNT; i++) {
			strategyToRun[i] = options.getBoolean(STRATEGY_NAMES[i], strategyToRun[i]);
		}
	}
	
	/**
	 * Initialises all selected analysing Strategies 
	 * @param program
	 * @param set
	 * @param monitor
	 * @param log
	 * @param suspiciousInstructions
	 */
	private void populateStrategyQueue(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log, List<String> suspiciousInstructions) {
		if(strategyToRun[0]) {
			queuedStrategies.add(new FindVMDetectionCPUInstructionStrategy(program, set, monitor, log, suspiciousInstructions, STRATEGY_NAMES[0]));
		}
		if(strategyToRun[1]){
			queuedStrategies.add(new FindVMDetectionUserComputerNamesStrategy(program, set, monitor, log, STRATEGY_NAMES[1]));
		}
		if(strategyToRun[2]){
			queuedStrategies.add(new FindVMDetectionRunningProcessesStrategy(program, set, monitor, log, STRATEGY_NAMES[2]));
		}
		if(strategyToRun[3]){
			queuedStrategies.add(new FindVMDetectionRunningServicesStrategy(program, set, monitor, log, STRATEGY_NAMES[3]));
		}
		if(strategyToRun[4]){
			queuedStrategies.add(new FindVMDetectionLoadedModulesMemoryScanningStrategy(program, set, monitor, log, STRATEGY_NAMES[4]));
		}
		if(strategyToRun[5]){
			queuedStrategies.add(new FindVMDetectionLoadedDriversDevicesStrategy(program, set, monitor, log, STRATEGY_NAMES[5]));
		}
		if(strategyToRun[6]){
			queuedStrategies.add(new FindVMDetectionFilesDirectorysStrategy(program, set, monitor, log, STRATEGY_NAMES[6]));
		}
		if(strategyToRun[7]){
			queuedStrategies.add(new FindVMDetectionRegistryKeyValuesStrategy(program, set, monitor, log, STRATEGY_NAMES[7]));
		}
		if(strategyToRun[8]){
			queuedStrategies.add(new FindVMDetectionMutexSemaphoresPortsStrategy(program, set, monitor, log, STRATEGY_NAMES[8]));
		}
	}
}
