package dev.slethware.montra.utility;

import dev.slethware.montra.models.response.ApiResponse;

public class ApiResponseUtil {

    public static <T> ApiResponse<T> successFullCreate(String message, T body){
        return new ApiResponse<>(message, 201, true, body);
    }

    public static <T> ApiResponse<T> successFull(String message, T body){
        return new ApiResponse<>(message, 200, true, body);
    }

    public static <T> ApiResponse<T> successFullVoid(String message){
        return new ApiResponse<>(message, 200, true, null);
    }
}
