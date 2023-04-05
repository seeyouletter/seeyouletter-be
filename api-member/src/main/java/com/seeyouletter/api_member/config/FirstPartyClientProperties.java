package com.seeyouletter.api_member.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Getter
@Component
@ConfigurationProperties(prefix = "first.party.client")
@RequiredArgsConstructor
public class FirstPartyClientProperties {

    private final List<String> origins;

}
