package dev.slethware.montra.utility;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class DateUtil {
    private static final DateTimeFormatter DEFAULT_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static LocalDateTime getCurrentUTC() {
        return LocalDateTime.now(ZoneOffset.UTC);
    }

    public static String formatToUTC(LocalDateTime dateTime) {
        return dateTime.atOffset(ZoneOffset.UTC).format(DEFAULT_FORMATTER);
    }
}
