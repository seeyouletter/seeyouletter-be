package com.seeyouletter.domain_letter;

import org.junit.jupiter.api.Disabled;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Disabled
@DataMongoTest
@Testcontainers
@ActiveProfiles(profiles = "test")
public abstract class MongoTestContext {

    @Container
    private static final MongoDBContainer MONGODB_CONTAINER;

    private static final String MONGODB_VERSION = "5.0.14";

    private static final String MONGODB_IMAGE = "mongo";

    static {
        MONGODB_CONTAINER = createMongoDBContainer();
    }

    private static MongoDBContainer createMongoDBContainer() {
        return new MongoDBContainer(createDockerImageName());
    }

    private static DockerImageName createDockerImageName() {
        return DockerImageName
                .parse(MONGODB_IMAGE)
                .withTag(MONGODB_VERSION);
    }

    @DynamicPropertySource
    static void registerDynamicProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.data.mongodb.uri", MONGODB_CONTAINER::getReplicaSetUrl);
    }

}
