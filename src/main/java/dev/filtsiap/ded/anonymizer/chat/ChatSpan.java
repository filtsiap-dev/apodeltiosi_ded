package dev.filtsiap.ded.anonymizer.chat;

import java.util.Objects;

/**
 * A half-open range {@code [start, end)} of CODE POINTS of the NFC-normalised input that must be
 * masked. {@code detector} is a diagnostic name only; nothing arbitrates on it.
 */
public record ChatSpan(int start, int end, PiiType type, String detector) {
    /**
     * Checks the range and the names.
     *
     * @throws IllegalArgumentException when {@code end} is before {@code start} or {@code start} is negative
     * @throws NullPointerException     when {@code type} or {@code detector} is null
     */
    public ChatSpan {
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("not a forward range: " + start + ".." + end);
        }
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(detector, "detector");
    }
}
