package com.seeyouletter.api_member;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seeyouletter.api_member.config.RestDocsConfiguration;
import org.junit.jupiter.api.Disabled;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

@Disabled
@Transactional
@AutoConfigureMockMvc
@AutoConfigureRestDocs
@SpringBootTest
@ContextConfiguration(classes = RestDocsConfiguration.class)
@ActiveProfiles(value = "test")
public abstract class IntegrationTestContext {

    private static final GenericContainer<?> REDIS_CONTAINER;

    private static final String REDIS_VERSION = "7.0.5";

    private static final String REDIS_IMAGE = "redis";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    static {
        REDIS_CONTAINER = createRedisContainer();
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

    @DynamicPropertySource
    static void registerDynamicProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.redis.port", () -> REDIS_CONTAINER.getFirstMappedPort() + "");
    }

}
