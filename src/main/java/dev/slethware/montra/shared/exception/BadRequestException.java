package dev.slethware.montra.shared.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@Setter
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {

    private HttpStatus status = HttpStatus.BAD_REQUEST;

    public BadRequestException(String message) { super(message); }

    public BadRequestException(String message, Throwable cause){
        super(message, cause);
    }
}
