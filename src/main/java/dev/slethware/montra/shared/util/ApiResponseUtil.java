package dev.slethware.montra.shared.util;

import dev.slethware.montra.shared.response.ApiResponse;

public class ApiResponseUtil {

    public static <T> ApiResponse<T> successfulCreate(String message, T body) {
        return new ApiResponse<>(message, 201, true, body);
    }

    public static <T> ApiResponse<T> successful(String message, T body) {
        return new ApiResponse<>(message, 200, true, body);
    }

    public static <T> ApiResponse<T> successfulVoid(String message) {
        return new ApiResponse<>(message, 200, true, null);
    }

    public static <T> ApiResponse<T> badRequest(String message) {
        return new ApiResponse<>(message, 400, false, null);
    }

    public static <T> ApiResponse<T> unauthorized(String message) {
        return new ApiResponse<>(message, 401, false, null);
    }

    public static <T> ApiResponse<T> forbidden(String message) {
        return new ApiResponse<>(message, 403, false, null);
    }

    public static <T> ApiResponse<T> notFound(String message) {
        return new ApiResponse<>(message, 404, false, null);
    }

    public static <T> ApiResponse<T> internalServerError(String message) {
        return new ApiResponse<>(message, 500, false, null);
    }
}