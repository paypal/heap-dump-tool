package com.paypal.heapdumptool.sanitizer;

/**
 * Display order for the {@code sanitize} and {@code capture} options, used by
 * {@code @Option(order = ...)} together with {@code sortOptions = false} on both commands.
 *
 * <p>Alphabetical order scatters related options: {@code --replacement} landed between {@code -f}
 * and {@code -s}, away from the {@code --target} that decides what it applies to. These constants
 * group them by what the user is deciding -- what to sanitize, what to write over it, what to spare,
 * then I/O and plumbing -- and sink the deprecated flags to the bottom.</p>
 *
 * <p>The values are spread by 10 so an option can be inserted into a group without renumbering.
 * A subcommand's own option takes a value from the group it belongs to when it has one -- {@code -z}
 * of {@code sanitize} sits with the deprecated flags -- and otherwise continues past every shared
 * value from {@link #CAPTURE_COMMAND_BASE}.</p>
 */
public final class OptionOrder {

    // what to sanitize, and what to write over it
    public static final int TARGET = 10;
    public static final int REPLACEMENT = 20;

    // what to spare
    public static final int EXCLUDE_STRING_FIELDS = 30;
    public static final int FORCE_STRING_CODER_MATCH = 40;

    // input and output
    public static final int BUFFER_SIZE = 60;

    // plumbing
    public static final int DOCKER_REGISTRY = 70;

    // deprecated, listed last
    public static final int LEGACY_BYTE_CHAR_ARRAYS_ONLY = 80;
    public static final int LEGACY_TEXT = 90;
    public static final int LEGACY_TEXT_CHARSET = 100;
    public static final int LEGACY_TAR_INPUT = 110;
    public static final int LEGACY_ZIP_OUTPUT = 120;

    /**
     * First order value available to the {@code capture} subcommand's own options.
     */
    public static final int CAPTURE_COMMAND_BASE = 300;

    private OptionOrder() {
        throw new AssertionError();
    }
}
