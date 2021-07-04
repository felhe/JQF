/**
 * 
 */
package edu.berkeley.cs.jqf.fuzz.ei;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.time.Duration;

/**
 * A guidance that performs coverage-guided fuzzing using two coverage maps,
 * one for all inputs and one for valid inputs only, that perform well.
 * 
 * @author Felix Leonard Heitmann
 * @author Stephan Druskat
 * @author Peter Wegmann
 */
public class PestGuidance extends ZestGuidance {
	
	/** Baseline number of mutated children to produce from a given parent input. */
	protected final int NUM_CHILDREN_BASELINE = 10;
	
	/** Multiplication factor for number of children to produce for favored inputs. */
	protected final int NUM_CHILDREN_MULTIPLIER_FAVORED = 50;

	/** Overriding the console used in ZestGuidance, TODO Check if this can be removed. */
    protected final PrintStream console = System.out;

	/**
	 * @param testName
	 * @param duration
	 * @param outputDirectory
	 * @throws IOException
	 */
	public PestGuidance(String testName, Duration duration, File outputDirectory) throws IOException {
		super(testName, duration, outputDirectory);
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
	}
	
    /* Returns the banner to be displayed on the status screen */
    protected String getTitle() {
        if (blind) {
            return  "Generator-based random fuzzing (no guidance)\n" +
                    "--------------------------------------------\n";
        } else {
            return  "Semantic Fuzzing with Pest\n" +
            		"(Pest is Performant Zest.)\n" +
                    "--------------------------\n";
        }
    }


}
