package dev.slethware.montra.shared.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@Setter
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorizedAccessException extends RuntimeException{
    private HttpStatus status = HttpStatus.UNAUTHORIZED;
    public UnauthorizedAccessException(String message) {
        super(message);
    }
    public UnauthorizedAccessException(String message, Throwable cause) { super(message, cause);}
}
