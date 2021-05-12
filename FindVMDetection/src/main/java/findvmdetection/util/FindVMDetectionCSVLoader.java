package findvmdetection.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * @author Jonas Schmucker
 *
 */
public class FindVMDetectionCSVLoader {
	private static final String COMMA_DELIMITER = ",";
	private File csvFile;

	public FindVMDetectionCSVLoader(File csvFile) {
		this.csvFile = csvFile;
	}
	
	/**
	 * 
	 * @return
	 * @throws IOException
	 */
	public List<String> getSuspiciousInstructions() throws IOException{
		
		FileReader in = new FileReader(csvFile);
		BufferedReader br = new BufferedReader(in);
	    String line = br.readLine();
	    in.close();
	    return Arrays.asList(line.split(COMMA_DELIMITER));
	}
	
}
