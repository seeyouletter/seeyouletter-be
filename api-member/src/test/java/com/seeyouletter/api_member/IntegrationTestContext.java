package com.seeyouletter.api_member;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.restdocs.operation.preprocess.OperationRequestPreprocessor;
import org.springframework.restdocs.operation.preprocess.OperationResponsePreprocessor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;

@Disabled
@Transactional
@AutoConfigureMockMvc
@AutoConfigureRestDocs
@SpringBootTest
@ActiveProfiles(value = "test")
public abstract class IntegrationTestContext {

    private static final GenericContainer<?> REDIS_CONTAINER;

    private static final String REDIS_VERSION = "7.0.5";

    private static final String REDIS_IMAGE = "redis";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    public static final OperationRequestPreprocessor REQUEST_PREPROCESSOR;

    public static final OperationResponsePreprocessor RESPONSE_PREPROCESSOR;

    static {
        REDIS_CONTAINER = createRedisContainer();
        REQUEST_PREPROCESSOR = createRequestPreprocessor();
        RESPONSE_PREPROCESSOR = createResponsePreprocessor();
        REDIS_CONTAINER.start();
    }

    private static GenericContainer<?> createRedisContainer() {
        return new GenericContainer<>(createRedisDockerImageName())
                .withExposedPorts(6379);
    }

    private static DockerImageName createRedisDockerImageName() {
        return DockerImageName
                .parse(REDIS_IMAGE)
                .withTag(REDIS_VERSION);
    }

    private static OperationRequestPreprocessor createRequestPreprocessor() {
        return preprocessRequest(
                prettyPrint(),
                modifyHeaders()
                        .remove("X-Forwarded-Host")
                        .remove("X-Forwarded-Proto")
                        .remove(CONTENT_LENGTH)
        );
    }

    private static OperationResponsePreprocessor createResponsePreprocessor() {
        return preprocessResponse(
                prettyPrint(),
                modifyHeaders()
                        .remove("X-Content-Type-Options")
                        .remove("X-XSS-Protection")
                        .remove("X-Frame-Options")
                        .remove("Pragma")
                        .remove(VARY)
                        .remove(CACHE_CONTROL)
                        .remove(EXPIRES)
                        .remove(CONTENT_LENGTH)
        );
    }

    @DynamicPropertySource
    static void registerDynamicProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.port", () -> REDIS_CONTAINER.getFirstMappedPort() + "");
    }

}
