package dev.slethware.montra.shared;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponseWrapper<T> {
    private String message;
    private Integer statusCode;
    private boolean isSuccessful;
    private T data;
}
