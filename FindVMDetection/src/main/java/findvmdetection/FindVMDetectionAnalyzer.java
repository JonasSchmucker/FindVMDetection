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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import findvmdetection.strategies.FindVMDetectionAnalyzingStrategyAbstract;
import findvmdetection.strategies.FindVMDetectionCPUInstructionStrategy;
import findvmdetection.strategies.FindVMDetectionFilesDirectorysStrategy;
import findvmdetection.strategies.FindVMDetectionLoadedDriversDevicesStrategy;
import findvmdetection.strategies.FindVMDetectionLoadedModulesMemoryScanningStrategy;
import findvmdetection.strategies.FindVMDetectionMutexSemaphoresPortsStrategy;
import findvmdetection.strategies.FindVMDetectionRegistryKeyValuesStrategy;
import findvmdetection.strategies.FindVMDetectionRunningProcessesStrategy;
import findvmdetection.strategies.FindVMDetectionRunningServicesStrategy;
import findvmdetection.strategies.FindVMDetectionUserComputerNamesStrategy;
import findvmdetection.util.FindVMDetectionBookmarks;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Platform;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds where Malware might detected a VM, and shows alternative behaviours for Host and VM
 *
 */
public class FindVMDetectionAnalyzer extends AbstractAnalyzer {

	private static final String VERBOSE = "Verbose";
	private static final String ANALYSER_SHORT_DESCRIPTION = "Finds where Malware might detected a VM, and shows alternative Behaviours for Host and VM";
	private static final String ANALYSER_NAME = "Find VM Detection";
	private static final String NO_STRATEGY_SELECTED = "No Strategy / Strategies selected";
	private static final String ANALYZER_WAS_CANCELLED_PER_USER_REQUEST = "Analyzer was cancelled per user request";
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
	
	
	public List<FindVMDetectionAnalyzingStrategyAbstract> queuedStrategies = new ArrayList<>();
	private boolean [] strategyToRun = new boolean [STRATEGY_COUNT];
	private boolean verbose = false;

	public FindVMDetectionAnalyzer() {
		super(ANALYSER_NAME,
				ANALYSER_SHORT_DESCRIPTION,
				AnalyzerType.INSTRUCTION_ANALYZER
			);
		
		Arrays.fill(strategyToRun, true);
		strategyToRun[0] = true; // "CPU Instruction Analysiss",
		strategyToRun[1] = true; // not yet implemented "User and Computer Names Analysis",
		strategyToRun[2] = true; // not yet implemented "Running Processes Analysis",
		strategyToRun[3] = true; // not yet implemented "Running Services Analysis",
		strategyToRun[4] = true; // not yet implemented "Loaded Modules and Memory Analysis",
		strategyToRun[5] = true; // "Loaded Drivers and Devices Analysis",
		strategyToRun[6] = true; // "Files and Directorys Analysis",
		strategyToRun[7] = true; // not yet implemented "Registry Keys Analysis",
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

		
		FindVMDetectionBookmarks vmBookmarks = new FindVMDetectionBookmarks(program.getBookmarkManager(), this);
		vmBookmarks.loadIcon();
		
		populateStrategyQueue(program, set, monitor, log, vmBookmarks);
		
		if(queuedStrategies.isEmpty()) {
			log.appendMsg(NO_STRATEGY_SELECTED);
			CancelledException e = new CancelledException(NO_STRATEGY_SELECTED);
			throw e;
		}
		
		FindVMDetectionAnalyzingStrategyAbstract.setOs(Platform.CURRENT_PLATFORM.getOperatingSystem());
		
		for(FindVMDetectionAnalyzingStrategyAbstract strategy : queuedStrategies) {
			strategy.verbose = verbose;
			strategy.init();
		}
		
		for(FindVMDetectionAnalyzingStrategyAbstract strategy : queuedStrategies) {
			if(monitor.isCancelled()) {
				CancelledException e = new CancelledException(ANALYZER_WAS_CANCELLED_PER_USER_REQUEST);
				throw e;
			}
			
			while(strategy.step() && !monitor.isCancelled()) {}
			
		}
		for(FindVMDetectionAnalyzingStrategyAbstract strategy : queuedStrategies) {
			strategy.printResults();
		}
		vmBookmarks.printResults();
		
		return true; //Analysis should have succeeded if this is reached
	}

	@Override
	public void analysisEnded(Program program) {
		super.analysisEnded(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {		
		//options.removeOption("Path to suspicious Mnemonics csv");
		for(int i = 0; i < STRATEGY_COUNT; i++) {
			options.registerOption(
					STRATEGY_NAMES[i],
					OptionType.BOOLEAN_TYPE,
					strategyToRun[i],
					null,
					STRATEGY_NAMES[i]
				);
		}
		
		options.registerOption(
				VERBOSE,
				OptionType.BOOLEAN_TYPE,
				false,
				null,
				VERBOSE.toLowerCase()
			);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		for(int i = 0; i < STRATEGY_COUNT; i++) {
			strategyToRun[i] = options.getBoolean(STRATEGY_NAMES[i], strategyToRun[i]);
		}
		verbose = options.getBoolean(VERBOSE, verbose);
	}
	
	/**
	 * Initialises all selected analysing Strategies 
	 * @param program
	 * @param set
	 * @param monitor
	 * @param log
	 * @param suspiciousInstructions
	 */
	private void populateStrategyQueue(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log, FindVMDetectionBookmarks vmBookmarks) {
		if(strategyToRun[0]) {
			queuedStrategies.add(new FindVMDetectionCPUInstructionStrategy(program, set, monitor, log, STRATEGY_NAMES[0], vmBookmarks));
		}
		if(strategyToRun[1]){
			queuedStrategies.add(new FindVMDetectionUserComputerNamesStrategy(program, set, monitor, log, STRATEGY_NAMES[1], vmBookmarks));
		}
		if(strategyToRun[2]){
			queuedStrategies.add(new FindVMDetectionRunningProcessesStrategy(program, set, monitor, log, STRATEGY_NAMES[2], vmBookmarks));
		}
		if(strategyToRun[3]){
			queuedStrategies.add(new FindVMDetectionRunningServicesStrategy(program, set, monitor, log, STRATEGY_NAMES[3], vmBookmarks));
		}
		if(strategyToRun[4]){
			queuedStrategies.add(new FindVMDetectionLoadedModulesMemoryScanningStrategy(program, set, monitor, log, STRATEGY_NAMES[4], vmBookmarks));
		}
		if(strategyToRun[5]){
			queuedStrategies.add(new FindVMDetectionLoadedDriversDevicesStrategy(program, set, monitor, log, STRATEGY_NAMES[5], vmBookmarks));
		}
		if(strategyToRun[6]){
			queuedStrategies.add(new FindVMDetectionFilesDirectorysStrategy(program, set, monitor, log, STRATEGY_NAMES[6], vmBookmarks));
		}
		if(strategyToRun[7]){
			queuedStrategies.add(new FindVMDetectionRegistryKeyValuesStrategy(program, set, monitor, log, STRATEGY_NAMES[7], vmBookmarks));
		}
		if(strategyToRun[8]){
			queuedStrategies.add(new FindVMDetectionMutexSemaphoresPortsStrategy(program, set, monitor, log, STRATEGY_NAMES[8], vmBookmarks));
		}
	}
}
