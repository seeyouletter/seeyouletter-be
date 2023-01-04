package com.seeyouletter.api_member;

import org.junit.jupiter.api.Disabled;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.restdocs.operation.preprocess.OperationRequestPreprocessor;
import org.springframework.restdocs.operation.preprocess.OperationResponsePreprocessor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;

@Disabled
@Transactional
@AutoConfigureMockMvc
@AutoConfigureRestDocs
@SpringBootTest
@ActiveProfiles(value = "test")
public abstract class IntegrationTestContext {

    @Autowired
    protected MockMvc mockMvc;

    public static final OperationRequestPreprocessor REQUEST_PREPROCESSOR;

    public static final OperationResponsePreprocessor RESPONSE_PREPROCESSOR;

    static {
        REQUEST_PREPROCESSOR = createRequestPreprocessor();
        RESPONSE_PREPROCESSOR = createResponsePreprocessor();
    }

    private static OperationRequestPreprocessor createRequestPreprocessor() {
        return preprocessRequest(
                removeHeaders(
                        "X-Forwarded-Host",
                        "X-Forwarded-Proto",
                        CONTENT_LENGTH
                ),
                modifyParameters()
                        .remove("_csrf"),
                prettyPrint()
        );
    }

    private static OperationResponsePreprocessor createResponsePreprocessor() {
        return preprocessResponse(
                prettyPrint(),
                removeHeaders(
                        "X-Content-Type-Options",
                        "X-XSS-Protection",
                        "X-Frame-Options",
                        "Pragma",
                        CACHE_CONTROL,
                        EXPIRES,
                        CONTENT_LENGTH
                )
        );
    }

}
