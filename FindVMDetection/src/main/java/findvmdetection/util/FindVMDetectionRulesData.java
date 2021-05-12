package findvmdetection.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import findvmdetection.ruleJsonData.*;

public class FindVMDetectionRulesData{
	public List<DLLRulesData> dlls = new ArrayList<>();

	public void populate(Object obj) {
		@SuppressWarnings("unchecked")
		HashMap<String, Object> top = (HashMap<String, Object>) obj;
		@SuppressWarnings("unchecked")
		ArrayList<Object> rules = (ArrayList<Object>) top.get("rules");
		for(Object od : rules) {
			@SuppressWarnings("unchecked")
			HashMap<String, Object> dll = (HashMap<String, Object>) od;
			DLLRulesData dllData = new DLLRulesData();
			dlls.add(dllData);
			dllData.dllName = (String) dll.get("DLL_Name");
			@SuppressWarnings("unchecked")
			ArrayList<Object> functions = (ArrayList<Object>) dll.get("Functions");
			for(Object of : functions) {
				@SuppressWarnings("unchecked")
				HashMap<String, Object> function = (HashMap<String, Object>) of;
				FunctionRulesData functionData = new FunctionRulesData();
				dllData.functions.add(functionData);
				functionData.functionName = (String) function.get("FunctionName");
				@SuppressWarnings("unchecked")
				ArrayList<Object> parameters = (ArrayList<Object>) function.get("forbiddenParams");
				for(Object op : parameters) {
					@SuppressWarnings("unchecked")
					HashMap<String,Object> parameter = (HashMap<String, Object>) op;
					ParameterRulesData parameterData = new ParameterRulesData();
					functionData.parameters.add(parameterData);
					parameterData.paramOrdinal = Math.toIntExact((long)parameter.get("paramOrdinal"));
					parameterData.paramType = (String) parameter.get("paramType");
					parameterData.forbiddenValue = (String) parameter.get("forbiddenValue");
				}
			}
		}
	}
}
