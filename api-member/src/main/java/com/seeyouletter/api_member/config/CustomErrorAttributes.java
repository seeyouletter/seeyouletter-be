package com.seeyouletter.api_member.config;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.lang.String.format;
import static javax.servlet.RequestDispatcher.*;
import static org.springframework.boot.web.error.ErrorAttributeOptions.Include.*;
import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
import static org.springframework.util.ObjectUtils.isEmpty;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

@Order(HIGHEST_PRECEDENCE)
public class CustomErrorAttributes implements ErrorAttributes, HandlerExceptionResolver, Ordered {

    private static final String ERROR_INTERNAL_ATTRIBUTE = CustomErrorAttributes.class.getName() + ".ERROR";

    @Override
    public int getOrder() {
        return HIGHEST_PRECEDENCE;
    }

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
                                         Exception exception) {
        storeErrorAttributes(request, exception);

        return null;
    }

    private void storeErrorAttributes(HttpServletRequest request, Exception exception) {
        request.setAttribute(ERROR_INTERNAL_ATTRIBUTE, exception);
    }

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> errorAttributes = getErrorAttributes(webRequest, options.isIncluded(STACK_TRACE));

        if (!options.isIncluded(EXCEPTION)) {
            errorAttributes.remove("exception");
        }

        if (!options.isIncluded(STACK_TRACE)) {
            errorAttributes.remove("trace");
        }

        if (!options.isIncluded(MESSAGE) && errorAttributes.get("message") != null) {
            errorAttributes.remove("message");
        }

        if (!options.isIncluded(BINDING_ERRORS)) {
            errorAttributes.remove("errors");

        }
        return errorAttributes;
    }

    private Map<String, Object> getErrorAttributes(WebRequest webRequest, boolean includeStackTrace) {
        Map<String, Object> errorAttributes = new LinkedHashMap<>();

        errorAttributes.put("timestamp", LocalDateTime.now());
        addStatus(errorAttributes, webRequest);
        addErrorDetails(errorAttributes, webRequest, includeStackTrace);
        addPath(errorAttributes, webRequest);

        return errorAttributes;
    }

    private void addStatus(Map<String, Object> errorAttributes, RequestAttributes requestAttributes) {
        Integer status = getAttribute(requestAttributes, ERROR_STATUS_CODE);

        if (status == null) {
            errorAttributes.put("status", 999);
            errorAttributes.put("error", "None");

            return;
        }

        errorAttributes.put("status", status);

        try {
            errorAttributes.put("error", HttpStatus.valueOf(status).getReasonPhrase());
        } catch (Exception ex) {
            errorAttributes.put("error", "Http Status " + status);
        }
    }

    private void addErrorDetails(Map<String, Object> errorAttributes, WebRequest webRequest, boolean includeStackTrace) {
        Throwable error = getError(webRequest);

        if (error != null) {
            while (error instanceof ServletException && error.getCause() != null) {
                error = error.getCause();
            }

            errorAttributes.put("exception", error.getClass().getName());

            if (includeStackTrace) {
                addStackTrace(errorAttributes, error);
            }
        }

        addErrorMessage(errorAttributes, webRequest, error);
    }

    private void addErrorMessage(Map<String, Object> errorAttributes, WebRequest webRequest, Throwable error) {
        BindingResult result = extractBindingResult(error);

        if (result == null) {
            addExceptionErrorMessage(errorAttributes, webRequest, error);
        } else {
            addBindingResultErrorMessage(errorAttributes, result);
        }
    }

    private void addExceptionErrorMessage(Map<String, Object> errorAttributes, WebRequest webRequest, Throwable error) {
        errorAttributes.put("message", getMessage(webRequest, error));
    }

    protected String getMessage(WebRequest webRequest, Throwable error) {
        Object message = getAttribute(webRequest, ERROR_MESSAGE);

        if (!isEmpty(message)) {
            return message.toString();
        }

        if (error != null && hasLength(error.getMessage())) {
            return error.getMessage();
        }

        return "No message available";
    }

    private void addBindingResultErrorMessage(Map<String, Object> errorAttributes, BindingResult result) {
        errorAttributes.put(
                "message",
                format(
                        "Validation failed for object='%s'. Error count: %s",
                        result.getObjectName(),
                        result.getErrorCount()
                )
        );
        errorAttributes.put("errors", result.getAllErrors());
    }

    private BindingResult extractBindingResult(Throwable error) {
        if (error instanceof BindingResult) {
            return (BindingResult) error;
        }

        return null;
    }

    private void addStackTrace(Map<String, Object> errorAttributes, Throwable error) {
        StringWriter stackTrace = new StringWriter();

        error.printStackTrace(new PrintWriter(stackTrace));
        stackTrace.flush();
        errorAttributes.put("trace", stackTrace.toString());
    }

    private void addPath(Map<String, Object> errorAttributes, RequestAttributes requestAttributes) {
        String path = getAttribute(requestAttributes, ERROR_REQUEST_URI);

        if (path != null) {
            errorAttributes.put("path", path);
        }
    }

    @Override
    public Throwable getError(WebRequest webRequest) {
        Throwable exception = getAttribute(webRequest, ERROR_INTERNAL_ATTRIBUTE);

        if (exception == null) {
            exception = getAttribute(webRequest, ERROR_EXCEPTION);
        }

        webRequest.setAttribute(ERROR_ATTRIBUTE, exception, SCOPE_REQUEST);

        return exception;
    }

    @SuppressWarnings("unchecked")
    private <T> T getAttribute(RequestAttributes requestAttributes, String name) {
        return (T) requestAttributes.getAttribute(name, SCOPE_REQUEST);
    }

}
