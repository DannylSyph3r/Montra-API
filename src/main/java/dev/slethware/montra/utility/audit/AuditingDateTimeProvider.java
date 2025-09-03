package dev.slethware.montra.utility.audit;

import dev.slethware.montra.utility.DateUtil;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

import java.time.temporal.TemporalAccessor;
import java.util.Optional;

@Component
public class AuditingDateTimeProvider implements DateTimeProvider {
    @Override
    public Optional<TemporalAccessor> getNow() {
        return Optional.of(DateUtil.getCurrentUTC());
    }
}
