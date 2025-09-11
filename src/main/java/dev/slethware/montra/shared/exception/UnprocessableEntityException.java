package dev.slethware.montra.shared.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@Getter
@Setter
@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class UnprocessableEntityException extends RuntimeException {
    private HttpStatus status = HttpStatus.UNPROCESSABLE_ENTITY;
    public UnprocessableEntityException(String message) { super(message);}
    public UnprocessableEntityException(String message, Throwable cause) { super(message, cause); }
}
