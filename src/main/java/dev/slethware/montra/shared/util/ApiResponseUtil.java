package dev.slethware.montra.shared.util;

import dev.slethware.montra.shared.ApiResponseWrapper;

public class ApiResponseUtil {

    public static <T> ApiResponseWrapper<T> successfulCreate(String message, T body) {
        return new ApiResponseWrapper<>(message, 201, true, body);
    }

    public static <T> ApiResponseWrapper<T> successful(String message, T body) {
        return new ApiResponseWrapper<>(message, 200, true, body);
    }

    public static <T> ApiResponseWrapper<T> successfulVoid(String message) {
        return new ApiResponseWrapper<>(message, 200, true, null);
    }

    public static <T> ApiResponseWrapper<T> badRequest(String message) {
        return new ApiResponseWrapper<>(message, 400, false, null);
    }

    public static <T> ApiResponseWrapper<T> unauthorized(String message) {
        return new ApiResponseWrapper<>(message, 401, false, null);
    }

    public static <T> ApiResponseWrapper<T> forbidden(String message) {
        return new ApiResponseWrapper<>(message, 403, false, null);
    }

    public static <T> ApiResponseWrapper<T> notFound(String message) {
        return new ApiResponseWrapper<>(message, 404, false, null);
    }

    public static <T> ApiResponseWrapper<T> internalServerError(String message) {
        return new ApiResponseWrapper<>(message, 500, false, null);
    }
}