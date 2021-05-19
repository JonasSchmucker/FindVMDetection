package findvmdetection.util;

import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.address.Address;

import javax.swing.ImageIcon;

import findvmdetection.FindVMDetectionAnalyzer;
import findvmdetection.strategies.FindVMDetectionAnalyzingStrategyAbstract;

import java.awt.Color;
import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FindVMDetectionBookmarks {
	private static final String FIND_VM_DETECTION_BOOKMARK_TYPE = "FindVMDetection";
	List<Bookmark> bookmarks = new ArrayList<>();
	private BookmarkType vmBookmark;
	private BookmarkManager bookmarkManager;
	public ImageIcon vmIcon;
	private File iconFile;
	private boolean verbose;
	private FindVMDetectionAnalyzer findVMDetectionAnalyzer;
	
	private Map<String, Integer> strategyNameToFoundOccurences = new HashMap<>();
	
	
	
	public FindVMDetectionBookmarks(BookmarkManager bookmarkManager, boolean verbose, FindVMDetectionAnalyzer findVMDetectionAnalyzer) {
		this.findVMDetectionAnalyzer = findVMDetectionAnalyzer;
		this.verbose = verbose;
		this.bookmarkManager = bookmarkManager;
		iconFile = Paths.get(System.getProperty("user.dir"))
				.resolve("src").resolve("main").resolve("resources").resolve("vm.ico")
				.toFile();
	}
	
	public void loadIcon() {
		vmIcon = new ImageIcon(iconFile.getAbsolutePath());
		vmBookmark = bookmarkManager.defineType(FIND_VM_DETECTION_BOOKMARK_TYPE, vmIcon, Color.BLUE, 0);
	}
	
	public void setBookmark(Address adress, FindVMDetectionAnalyzingStrategyAbstract strategy) {
		strategyNameToFoundOccurences.merge(strategy.strategyName, 1, (i, j) -> i + j);
		Bookmark bookmarkToAdd 
			= bookmarkManager.setBookmark(
											adress, vmBookmark.getTypeString(), 
											strategy.strategyName, 
											"Might be used to distiguish between VM and Host"
										);
		bookmarks.add(bookmarkToAdd);
	}
	
	public void printResults() {
		for(FindVMDetectionAnalyzingStrategyAbstract strategy: findVMDetectionAnalyzer.queuedStrategies) {
			strategy.printMessage("Found " + strategyNameToFoundOccurences.get(strategy.strategyName) + " Occurences", false);
		}
	}
}
