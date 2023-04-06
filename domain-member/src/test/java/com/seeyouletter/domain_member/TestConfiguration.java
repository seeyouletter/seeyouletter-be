package com.seeyouletter.domain_member;

import com.seeyouletter.domain_member.config.DomainMemberAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@Import(value = DomainMemberAutoConfiguration.class)
@SpringBootApplication
public class TestConfiguration {
}
