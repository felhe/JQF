/**
 * 
 */
package edu.berkeley.cs.jqf.fuzz.ei;

import java.io.File;
import java.io.IOException;
import java.time.Duration;

/**
 * @author Stephan Druskat
 *
 */
public class PestGuidance extends ZestGuidance {

	/**
	 * @param testName
	 * @param duration
	 * @param outputDirectory
	 * @throws IOException
	 */
	public PestGuidance(String testName, Duration duration, File outputDirectory) throws IOException {
		super(testName, duration, outputDirectory);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param testName
	 * @param duration
	 * @param outputDirectory
	 * @param seedInputFiles
	 * @throws IOException
	 */
	public PestGuidance(String testName, Duration duration, File outputDirectory, File[] seedInputFiles)
			throws IOException {
		super(testName, duration, outputDirectory, seedInputFiles);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param testName
	 * @param duration
	 * @param outputDirectory
	 * @param seedInputDir
	 * @throws IOException
	 */
	public PestGuidance(String testName, Duration duration, File outputDirectory, File seedInputDir)
			throws IOException {
		super(testName, duration, outputDirectory, seedInputDir);
		// TODO Auto-generated constructor stub
	}

}
