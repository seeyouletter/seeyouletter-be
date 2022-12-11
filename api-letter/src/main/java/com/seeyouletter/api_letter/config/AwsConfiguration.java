package com.seeyouletter.api_letter.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;

import java.net.URI;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(value = {AwsProperties.class})
public class AwsConfiguration {

    private final AwsProperties awsProperties;

    @Bean
    public AwsCredentialsProvider awsCredentialsProvider() {
        DefaultCredentialsProvider defaultCredentials = DefaultCredentialsProvider.create();

        StaticCredentialsProvider localStackCredentials = StaticCredentialsProvider.create(
                AwsBasicCredentials.create(
                        "accessKey",
                        "secretKey"
                )
        );

        return AwsCredentialsProviderChain.of(defaultCredentials, localStackCredentials);
    }

    @Bean
    public S3Client s3Client(AwsCredentialsProvider awsCredentialsProvider) {
        S3ClientBuilder s3ClientBuilder = S3Client
                .builder()
                .credentialsProvider(awsCredentialsProvider)
                .region(Region.of(awsProperties.getS3().getRegion()));

        if (StringUtils.hasText(awsProperties.getEndpoint())) {
            s3ClientBuilder.endpointOverride(URI.create(awsProperties.getEndpoint()));
        }

        return s3ClientBuilder.build();
    }

}
