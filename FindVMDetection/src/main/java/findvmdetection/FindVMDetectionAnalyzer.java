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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds where Malware might detected a VM, and shows alternative Behaviours for Host and VM
 */
public class FindVMDetectionAnalyzer extends AbstractAnalyzer {

	public FindVMDetectionAnalyzer() {


		super("Find VM Detection",
				"Finds where Malware might detected a VM, and shows alternative Behaviours for Host and VM",
				AnalyzerType.INSTRUCTION_ANALYZER
			);
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

	/*@Override
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		//options.registerOption("Option name goes here", false, null,"Option description goes here");
	}*/

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		FindVMDetectionLogic logic = new FindVMDetectionLogic(program, set, monitor, log);
		
		while(logic.step() && !monitor.isCancelled()) {}

		if(monitor.isCancelled()) {
			CancelledException e = new CancelledException("Analyzer was cancelled per user request");
			throw e;
		}
		
		return true; //Analysis should have succeeded if this is reached
	}
	
	@Override
	public void analysisEnded(Program program) {
		super.analysisEnded(program);
	}
}
