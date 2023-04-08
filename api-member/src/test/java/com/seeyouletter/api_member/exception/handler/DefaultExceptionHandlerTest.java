package com.seeyouletter.api_member.exception.handler;

import com.seeyouletter.api_member.controller.DefaultController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.validation.BindException;
import org.springframework.validation.ObjectError;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName(value = "전역 에러 핸들러 테스트")
@WithMockUser
@ExtendWith(value = MockitoExtension.class)
@WebMvcTest(controllers = DefaultController.class)
class DefaultExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DefaultController defaultController;

    @DisplayName(value = "500 에러 핸들링")
    @Test
    void handleInternalServerError() throws Exception {
        when(defaultController.index()).thenThrow(new RuntimeException());

        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.status").value(INTERNAL_SERVER_ERROR.value()))
                .andExpect(jsonPath("$.error").value(INTERNAL_SERVER_ERROR.getReasonPhrase()))
                .andExpect(jsonPath("$.message").exists());
    }

    @DisplayName(value = "400 에러 핸들링")
    @Test
    void handleBadRequest() throws Exception {
        BindException bindException = mock(BindException.class);
        ObjectError objectError = mock(ObjectError.class);
        String defaultMessage = "테스트 에러 발생";

        when(bindException.getAllErrors()).thenReturn(List.of(objectError));
        when(objectError.getDefaultMessage()).thenReturn(defaultMessage);


        when(defaultController.index()).thenAnswer(i -> {
            throw bindException;
        });

        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.status").value(BAD_REQUEST.value()))
                .andExpect(jsonPath("$.error").value(BAD_REQUEST.getReasonPhrase()))
                .andExpect(jsonPath("$.message").value(defaultMessage));
    }

    @DisplayName(value = "예외가 발생하지 않은 경우는 예외 핸들링 제외")
    @Test
    void doNotHandleWhenNotThrowException() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.timestamp").doesNotExist())
                .andExpect(jsonPath("$.status").doesNotExist())
                .andExpect(jsonPath("$.error").doesNotExist())
                .andExpect(jsonPath("$.message").doesNotExist());
    }

}
