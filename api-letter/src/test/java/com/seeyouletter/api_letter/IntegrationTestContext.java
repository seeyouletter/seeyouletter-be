package com.seeyouletter.api_letter;

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
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Paths;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.testcontainers.containers.BindMode.READ_ONLY;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.S3;

@Disabled
@AutoConfigureMockMvc
@AutoConfigureRestDocs
@SpringBootTest
@ActiveProfiles(profiles = "test")
public abstract class IntegrationTestContext {

    private static final MongoDBContainer MONGODB_CONTAINER;

    public static final LocalStackContainer LOCAL_STACK_CONTAINER;

    private static final String MONGODB_VERSION = "5.0.14";

    private static final String MONGODB_IMAGE = "mongo";

    private static final String LOCAL_STACK_VERSION = "0.11.3";

    private static final String LOCAL_STACK_IMAGE = "localstack/localstack";

    public static final OperationRequestPreprocessor REQUEST_PREPROCESSOR;

    public static final OperationResponsePreprocessor RESPONSE_PREPROCESSOR;

    @Autowired
    protected MockMvc mockMvc;

    static {
        MONGODB_CONTAINER = createMongoDBContainer();
        LOCAL_STACK_CONTAINER = createLocalStackContainer();
        REQUEST_PREPROCESSOR = createRequestPreprocessor();
        RESPONSE_PREPROCESSOR = createResponsePreprocessor();
        MONGODB_CONTAINER.start();
        LOCAL_STACK_CONTAINER.start();
    }

    private static MongoDBContainer createMongoDBContainer() {
        return new MongoDBContainer(createMongoDBDockerImageName());
    }

    private static LocalStackContainer createLocalStackContainer() {
        return new LocalStackContainer(createLocalStackImageName())
                .withServices(S3)
                .withFileSystemBind(
                        parseLocalStackInitScriptPath(),
                        "/docker-entrypoint-initaws.d",
                        READ_ONLY
                );
    }

    private static String parseLocalStackInitScriptPath() {
        return Paths
                .get("")
                .toAbsolutePath()
                .getParent()
                .resolve("docker")
                .resolve("localstack")
                .normalize()
                .toString();
    }

    private static DockerImageName createMongoDBDockerImageName() {
        return DockerImageName
                .parse(MONGODB_IMAGE)
                .withTag(MONGODB_VERSION);
    }

    private static DockerImageName createLocalStackImageName() {
        return DockerImageName
                .parse(LOCAL_STACK_IMAGE)
                .withTag(LOCAL_STACK_VERSION);
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
                        .remove(CACHE_CONTROL)
                        .remove(EXPIRES)
                        .remove(CONTENT_LENGTH)
        );
    }

    @DynamicPropertySource
    static void registerDynamicProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.data.mongodb.uri", MONGODB_CONTAINER::getReplicaSetUrl);
        registry.add("aws.endpoint", () -> LOCAL_STACK_CONTAINER.getEndpointOverride(S3).toString());
    }

}
