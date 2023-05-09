package com.seeyouletter.api_member.exception.handler;

import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;

import static com.seeyouletter.api_member.exception.handler.DefaultErrorResponse.badRequest;
import static com.seeyouletter.api_member.exception.handler.DefaultErrorResponse.serverError;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestControllerAdvice
public class DefaultExceptionHandler {

    @ExceptionHandler(value = Exception.class)
    @ResponseStatus(code = INTERNAL_SERVER_ERROR)
    public DefaultErrorResponse handle(HttpServletRequest request) {
        return serverError(request.getRequestURI());
    }

    @ExceptionHandler(value = BindException.class)
    @ResponseStatus(code = BAD_REQUEST)
    public DefaultErrorResponse handle(BindException exception, HttpServletRequest request) {
        String message = exception
                .getAllErrors()
                .get(0)
                .getDefaultMessage();

        return badRequest(request.getRequestURI(), message);
    }

}
