package findvmdetection;

/**
 * @author Jonas Schmucker
 *
 */
public interface FindVMDetectionAnalyzingStrategyInterface {
	/**
	 * Atomic step of the Analyzing Strategy, Analyzing process may be cancelled in between steps
	 * @return false to terminate this strategy
	 */
	public boolean step();
}
