package com.seeyouletter.api_member.exception.handler;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

import static java.time.LocalDateTime.now;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Getter
@RequiredArgsConstructor
public class DefaultErrorResponse {

    private final LocalDateTime timestamp = now();

    private final int status;

    private final String error;

    private final String path;

    private final String message;

    public static DefaultErrorResponse badRequest(String path, String message) {
        return new DefaultErrorResponse(
                BAD_REQUEST.value(),
                BAD_REQUEST.getReasonPhrase(),
                path,
                message
        );
    }

    public static DefaultErrorResponse serverError(String path) {
        return new DefaultErrorResponse(
                INTERNAL_SERVER_ERROR.value(),
                INTERNAL_SERVER_ERROR.getReasonPhrase(),
                path,
                "서버 에러가 발생했습니다. 개발자에게 문의해주세요!"
        );
    }

}
