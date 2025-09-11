package dev.slethware.montra.shared.util;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class DateUtil {

    public static LocalDateTime getCurrentUTC() {
        return LocalDateTime.now(ZoneOffset.UTC);
    }

    public static LocalDateTime toUTC(LocalDateTime localDateTime) {
        return localDateTime.atZone(ZoneOffset.systemDefault()).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
    }
}