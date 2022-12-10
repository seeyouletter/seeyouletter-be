package com.seeyouletter.api_sample.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@Getter
@RequiredArgsConstructor
@ConstructorBinding
@ConfigurationProperties("aws")
public class AwsProperties {

    private final String endpoint;

    private final S3 s3;

    @Getter
    @RequiredArgsConstructor
    public static final class S3 {

        private final String region;

    }

}
