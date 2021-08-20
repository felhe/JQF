/**
 * 
 */
package edu.berkeley.cs.jqf.fuzz.ei;

import java.io.File;

import org.junit.runner.Result;

import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

/**
 * Entry point for fuzzing with Pest.
 * 
 * <p>Mostly copied from {@link ZestDriver}.</p>
 *
 * @author Rohan Padhye
 * @author Stephan Druskat {@literal <mail@sdruskat.net>}
 *
 */
public class PestDriver extends ZestDriver {

	public static void main(String[] args) {
        if (args.length < 2){
            System.err.println("Usage: java " + PestDriver.class + " TEST_CLASS TEST_METHOD [OUTPUT_DIR [SEED_DIR | SEED_FILES...]]");
            System.exit(1);
        }

        String testClassName  = args[0];
        String testMethodName = args[1];
        String outputDirectoryName = args.length > 2 ? args[2] : "fuzz-results";
        File outputDirectory = new File(outputDirectoryName);
        File[] seedFiles = null;
        if (args.length > 3) {
            seedFiles = new File[args.length-3];
            for (int i = 3; i < args.length; i++) {
                seedFiles[i-3] = new File(args[i]);
            }
        }

        try {
            // Load the guidance
            String title = testClassName+"#"+testMethodName;
            PestGuidance guidance = null;

            if (seedFiles == null) {
                guidance = new PestGuidance(title, null, outputDirectory);
            } else if (seedFiles.length == 1 && seedFiles[0].isDirectory()) {
                guidance = new PestGuidance(title, null, outputDirectory, seedFiles[0]);
            } else {
                guidance = new PestGuidance(title, null, outputDirectory, seedFiles);
            }


            // Run the Junit test
            Result res = GuidedFuzzing.run(testClassName, testMethodName, guidance, System.out);
            if (Boolean.getBoolean("jqf.logCoverage")) {
                System.out.println(String.format("Covered %d edges.",
                        guidance.getTotalCoverage().getNonZeroCount()));
            }
            if (Boolean.getBoolean("jqf.ei.EXIT_ON_CRASH") && !res.wasSuccessful()) {
                System.exit(3);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }
}
