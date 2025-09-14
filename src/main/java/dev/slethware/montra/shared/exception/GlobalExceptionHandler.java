package dev.slethware.montra.shared.exception;

import dev.slethware.montra.shared.ApiResponseWrapper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {


    // Existing exception handlers
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiResponseWrapper<?>> badRequestExceptionHandler(BadRequestException e) {
        log.error(e.getMessage(), e);
        return new ResponseEntity<>(new ApiResponseWrapper<>(e.getMessage(), e.getStatus().value(), false, null), e.getStatus());
    }

    @ExceptionHandler(UnauthorizedAccessException.class)
    public ResponseEntity<ApiResponseWrapper<?>> unauthorizedRequestExceptionHandler(UnauthorizedAccessException e) {
        log.error(e.getMessage(), e);
        return new ResponseEntity<>(new ApiResponseWrapper<>(e.getMessage(), e.getStatus().value(), false, null), e.getStatus());
    }

    @ExceptionHandler(InternalServerException.class)
    public ResponseEntity<ApiResponseWrapper<?>> internalServerExceptionHandler(InternalServerException e) {
        log.error(e.getMessage(), e);
        return new ResponseEntity<>(new ApiResponseWrapper<>(e.getMessage(), e.getStatus().value(), false, null), e.getStatus());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponseWrapper<?>> resourceNotFoundExceptionHandler(ResourceNotFoundException e) {
        log.error(e.getMessage(), e);
        return new ResponseEntity<>(new ApiResponseWrapper<>(e.getMessage(), e.getStatus().value(), false, null), e.getStatus());
    }

    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<ApiResponseWrapper<?>> authorizationDeniedExceptionHandler(AuthorizationDeniedException e) {
        log.error(e.getMessage(), e);
        return new ResponseEntity<>(new ApiResponseWrapper<>(e.getMessage(), 403, false, null), HttpStatus.FORBIDDEN);
    }

//    @Override
//    protected ResponseEntity<Object> handleMaxUploadSizeExceededException(
//            MaxUploadSizeExceededException ex,
//            HttpHeaders headers,
//            HttpStatusCode status,
//            WebRequest request) {
//
//        log.error("File upload size exceeded: {}", ex.getMessage(), ex);
//
//        String actualSize = "unknown";
//        if (request instanceof ServletWebRequest) {
//            HttpServletRequest servletRequest = ((ServletWebRequest) request).getRequest();
//            long contentLength = servletRequest.getContentLengthLong();
//            if (contentLength > 0) {
//                actualSize = formatSize(contentLength);
//            }
//        }
//
//        Map<String, String> data = new HashMap<>();
//        data.put("uploadedFileSize", actualSize);
//        data.put("maxAllowedSize", maxFileSize);
//
//        var response = ApiResponseWrapper.builder()
//                .message("File upload error: Maximum upload size exceeded")
//                .statusCode(HttpStatus.PAYLOAD_TOO_LARGE.value())
//                .isSuccessful(false)
//                .data(data)
//                .build();
//
//        return new ResponseEntity<>(response, HttpStatus.PAYLOAD_TOO_LARGE);
//    }

    // Existing override methods
    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(
            HttpRequestMethodNotSupportedException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode status,
            @NonNull WebRequest request) {

        log.error(ex.getMessage(), ex);
        var response = ApiResponseWrapper.builder()
                .message(ex.getMessage())
                .statusCode(status.value())
                .isSuccessful(false)
                .build();

        return new ResponseEntity<>(response, HttpStatus.METHOD_NOT_ALLOWED);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode statusCode,
            @NonNull WebRequest request) {
        log.error(ex.getMessage(), ex);

        Map<String, String> data = new HashMap<>();
        HttpStatus status = HttpStatus.BAD_REQUEST;

        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            data.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        var response = ApiResponseWrapper.builder()
                .data(data)
                .message("Invalid Arguments")
                .statusCode(status.value())
                .isSuccessful(false)
                .build();

        return new ResponseEntity<>(response, status);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex, Object body,
            @NonNull HttpHeaders headers,
            @NonNull HttpStatusCode statusCode,
            @NonNull WebRequest request) {

        log.error(ex.getMessage(), ex);
        var response = ApiResponseWrapper.builder()
                .message(ex.getMessage())
                .statusCode(statusCode.value())
                .isSuccessful(false)
                .build();
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleUnpredictableException(Exception ex) {
        log.error(ex.getMessage(), ex);
        var response = ApiResponseWrapper.builder()
                .message(ex.getMessage())
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .isSuccessful(false)
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // Helper method for file size formatting
//    private String formatSize(long bytes) {
//        if (bytes < 1024) return bytes + " B";
//        int exp = (int) (Math.log(bytes) / Math.log(1024));
//        String pre = "KMGTPE".charAt(exp - 1) + "";
//        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
//    }
}