package com.seeyouletter.api_sample;

import org.junit.jupiter.api.Disabled;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Paths;

import static org.testcontainers.containers.BindMode.READ_ONLY;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.S3;

@Disabled
@SpringBootTest
@Testcontainers
@ActiveProfiles(profiles = "test")
public abstract class IntegrationTestContext {

    @Container
    private static final MongoDBContainer MONGODB_CONTAINER;

    @Container
    public static final LocalStackContainer LOCAL_STACK_CONTAINER;

    private static final String MONGODB_VERSION = "5.0.14";

    private static final String MONGODB_IMAGE = "mongo";

    private static final String LOCAL_STACK_VERSION = "0.11.3";

    private static final String LOCAL_STACK_IMAGE = "localstack/localstack";

    static {
        MONGODB_CONTAINER = createMongoDBContainer();
        LOCAL_STACK_CONTAINER = createLocalStackContainer();
    }

    private static MongoDBContainer createMongoDBContainer() {
        return new MongoDBContainer(createDockerImageName());
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

    private static DockerImageName createDockerImageName() {
        return DockerImageName
                .parse(MONGODB_IMAGE)
                .withTag(MONGODB_VERSION);
    }

    private static DockerImageName createLocalStackImageName() {
        return DockerImageName
                .parse(LOCAL_STACK_IMAGE)
                .withTag(LOCAL_STACK_VERSION);
    }

    @DynamicPropertySource
    static void registerDynamicProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.data.mongodb.uri", MONGODB_CONTAINER::getReplicaSetUrl);
        registry.add("aws.endpoint", () -> LOCAL_STACK_CONTAINER.getEndpointOverride(S3).toString());
    }

}
