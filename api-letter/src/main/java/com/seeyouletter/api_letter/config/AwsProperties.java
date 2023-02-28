package com.seeyouletter.api_letter.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@RequiredArgsConstructor
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
