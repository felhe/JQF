/**
 * 
 */
package edu.berkeley.cs.jqf.fuzz.ei;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.util.Coverage;

/**
 * A guidance that performs coverage-guided fuzzing using two coverage maps, one
 * for all inputs and one for valid inputs only, that perform well.
 * 
 * @author Felix Leonard Heitmann
 * @author Stephan Druskat {@literal <mail@sdruskat.net>}
 * @author Peter Wegmann
 */
public class PestGuidance extends ZestGuidance {

	/** Baseline number of mutated children to produce from a given parent input. */
	protected final int NUM_CHILDREN_BASELINE = 10;

	/**
	 * Multiplication factor for number of children to produce for favored inputs.
	 */
	protected final int NUM_CHILDREN_MULTIPLIER_FAVORED = 50;

	/**
	 * Overriding the console used in ZestGuidance, TODO Check if this can be
	 * removed.
	 */
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
	@Override
	protected String getTitle() {
		if (blind) {
			return "Generator-based random fuzzing (no guidance)\n" + "--------------------------------------------\n";
		} else {
			return "Semantic Fuzzing with Pest\n" + "(Pest is Performant Zest.)\n" + "--------------------------\n";
		}
	}

	@Override
	protected int getTargetChildrenForParent(Input parentInput) {
		// Baseline is a constant
		int target = NUM_CHILDREN_BASELINE;

		// We like inputs that cover many things, so scale with fraction of max that
		// counts responsibilities
		if (maxCoverage > 0) {
			target += (NUM_CHILDREN_MULTIPLIER_FAVORED * parentInput.responsibilities.size()) / maxCoverage;
		}

		return target;
	}

	/**
	 * Purges the queue before completing the fuzzing cycle
	 */
	@Override
	protected void completeCycle() {
		purgeQueue();
		super.completeCycle();
	}

	private void purgeQueue() {
		infoLog("Purging input queue.");
		// sort input by performance
		savedInputs.sort((first, second) -> {
			if (first.valid && !second.valid)
				return -1;
			if (!first.valid && second.valid)
				return 1;
			return first.coverage.performanceScore - second.coverage.performanceScore;
		});
		Collection<Integer> coveredBranches = new ArrayList<Integer>(totalCoverage.getCovered());
		ArrayList<Input<?>> toRemove = new ArrayList<>();
		for (Input<?> input : savedInputs) {
			if (!coveredBranches.isEmpty()) {
				for (Integer b : input.coverage.getCovered()) {
					if (coveredBranches.contains(b)) {
						Input<?> oldResponsible = responsibleInputs.get(b);
						if (oldResponsible != null) {
							oldResponsible.responsibilities.remove(b);
						}
						// We are now responsible
						responsibleInputs.put(b, input);
						input.responsibilities.add(b);
						coveredBranches.remove(b);
					}
				}
			}
			if (input.responsibilities.size() == 0) {
				toRemove.add(input);
			}
		}
		this.savedInputs.removeAll(toRemove);
		if (toRemove.size() > 0)
			console.printf("Removed %s subsumed inputs with poor performance\n", toRemove.size());
	}

	/**
	 * Overrides result-handling from {@link ZestGuidance} 
	 * to achieve better performance:
	 * 
	 * <p>
	 * <ul>
	 * <li>responsibilities are reset on success,</li>
	 * <li>a performance score is calculated to 
	 * be reused in the selection of next generation inputs,</li>
	 * <li>introduces the custom flag `+reduce`</li>
	 * </ul>
	 * </p>
	 * 
	 * <p>
	 * Mostly copied from {@link ZestGuidance}.
	 * </p>
	 */
	@Override
	public void handleResult(Result result, Throwable error) throws GuidanceException {
		conditionallySynchronize(multiThreaded, () -> {
			// Stop timeout handling
			this.runStart = null;

			// Increment run count
			this.numTrials++;

			boolean valid = result == Result.SUCCESS;

			if (valid) {
				// Increment valid counter
				numValid++;
			}

			if (result == Result.SUCCESS || (result == Result.INVALID && SAVE_ONLY_VALID == false)) {

				// Coverage before
				int nonZeroBefore = totalCoverage.getNonZeroCount();
				int validNonZeroBefore = validCoverage.getNonZeroCount();

				// Reset responsibilities and calculate performance score
				Set<Object> responsibilities = new HashSet<>();
				runCoverage.calculatePerformanceScore();

				// Update total coverage
				boolean coverageBitsUpdated = totalCoverage.updateBits(runCoverage);
				if (valid) {
					validCoverage.updateBits(runCoverage);
				}

				// Coverage after
				int nonZeroAfter = totalCoverage.getNonZeroCount();
				if (nonZeroAfter > maxCoverage) {
					maxCoverage = nonZeroAfter;
				}
				int validNonZeroAfter = validCoverage.getNonZeroCount();

				// Possibly save input
				boolean toSave = false;
				String why = "";

				if (!DISABLE_SAVE_NEW_COUNTS && coverageBitsUpdated) {
					toSave = true;
					why = why + "+reduce";
				}

				// Save if new total coverage found
				if (nonZeroAfter > nonZeroBefore) {
					// Must be responsible for some branch
					assert (responsibilities.size() > 0);
					toSave = true;
					why = why + "+cov";
				}

				// Save if new valid coverage is found
				if (this.validityFuzzing && validNonZeroAfter > validNonZeroBefore) {
					// Must be responsible for some branch
					assert (responsibilities.size() > 0);
					currentInput.valid = true;
					toSave = true;
					why = why + "+valid";
				}

				if (toSave) {

					// Trim input (remove unused keys)
					currentInput.gc();

					// It must still be non-empty
					assert (currentInput.size() > 0) : String.format("Empty input: %s", currentInput.desc);

					// libFuzzerCompat stats are only displayed when they hit new coverage
					if (LIBFUZZER_COMPAT_OUTPUT) {
						displayStats();
					}

					infoLog("Saving new input (at run %d): " + "input #%d " + "of size %d; " + "total coverage = %d",
							numTrials, savedInputs.size(), currentInput.size(), nonZeroAfter);

					// Save input to queue and to disk
					final String reason = why;
					GuidanceException.wrap(() -> saveCurrentInput(responsibilities, reason));
				}
			} else if (result == Result.FAILURE || result == Result.TIMEOUT) {
				String msg = error.getMessage();

				// Get the root cause of the failure
				Throwable rootCause = error;
				while (rootCause.getCause() != null) {
					rootCause = rootCause.getCause();
				}

				// Attempt to add this to the set of unique failures
				if (uniqueFailures.add(Arrays.asList(rootCause.getStackTrace()))) {

					// Trim input (remove unused keys)
					currentInput.gc();

					// It must still be non-empty
					assert (currentInput.size() > 0) : String.format("Empty input: %s", currentInput.desc);

					// Save crash to disk
					int crashIdx = uniqueFailures.size() - 1;
					String saveFileName = String.format("id_%06d", crashIdx);
					File saveFile = new File(savedFailuresDirectory, saveFileName);
					GuidanceException.wrap(() -> writeCurrentInputToFile(saveFile));
					infoLog("%s", "Found crash: " + error.getClass() + " - " + (msg != null ? msg : ""));
					String how = currentInput.desc;
					String why = result == Result.FAILURE ? "+crash" : "+hang";
					infoLog("Saved - %s %s %s", saveFile.getPath(), how, why);

					if (EXACT_CRASH_PATH != null && !EXACT_CRASH_PATH.equals("")) {
						File exactCrashFile = new File(EXACT_CRASH_PATH);
						GuidanceException.wrap(() -> writeCurrentInputToFile(exactCrashFile));
					}

					// libFuzzerCompat stats are only displayed when they hit new coverage or
					// crashes
					if (LIBFUZZER_COMPAT_OUTPUT) {
						displayStats();
					}
				}
			}

			// displaying stats on every interval is only enabled for AFL-like stats screen
			if (!LIBFUZZER_COMPAT_OUTPUT) {
				displayStats();
			}

			// Save input unconditionally if such a setting is enabled
			if (LOG_ALL_INPUTS) {
				File logDirectory = new File(allInputsDirectory, result.toString().toLowerCase());
				String saveFileName = String.format("id_%09d", numTrials);
				File saveFile = new File(logDirectory, saveFileName);
				GuidanceException.wrap(() -> writeCurrentInputToFile(saveFile));
			}
		});
	}

	/* Saves an interesting input to the queue. */
    protected void saveCurrentInput(Set<Object> responsibilities, String why) throws IOException {

        // First, save to disk (note: we issue IDs to everyone, but only write to disk  if valid)
        int newInputIdx = numSavedInputs++;
        String saveFileName = String.format("id_%06d", newInputIdx);
        String how = currentInput.desc;
        File saveFile = new File(savedCorpusDirectory, saveFileName);
        writeCurrentInputToFile(saveFile);
        infoLog("Saved - %s %s %s", saveFile.getPath(), how, why);

        // If not using guidance, do nothing else
        if (blind) {
            return;
        }

        // Second, save to queue
        savedInputs.add(currentInput);

        // Third, store basic book-keeping data
        currentInput.id = newInputIdx;
        currentInput.saveFile = saveFile;
        currentInput.coverage = new Coverage(runCoverage);
        currentInput.nonZeroCoverage = runCoverage.getNonZeroCount();
        currentInput.offspring = 0;
        savedInputs.get(currentParentInputIdx).offspring += 1;

        // Fourth, neglect resonsibilities
        currentInput.responsibilities = new HashSet<>();
    }

}
