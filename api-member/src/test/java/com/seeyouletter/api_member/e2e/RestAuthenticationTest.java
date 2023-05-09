package com.seeyouletter.api_member.e2e;

import com.seeyouletter.api_member.IntegrationTestContext;
import com.seeyouletter.api_member.auth.value.LoginRequest;
import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.repository.UserRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static com.seeyouletter.domain_member.enums.GenderType.MALE;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Rest API 로그인")
class RestAuthenticationTest extends IntegrationTestContext {

    private static final String loginPath = "/login";
    private static final String testUsername = "test@seeyouletter.kr";
    private static final String testPassword = "password";
    private static final String testFailUsername = "fail@seeyouletter.kr";
    private static final String testFailPassword = "failPassword";

    @BeforeAll
    static void registerUser(@Autowired UserRepository userRepository,
                             @Autowired PasswordEncoder passwordEncoder){
        userRepository.save(createUser(passwordEncoder));
    }

    @Test
    @DisplayName("success")
    void successLogin() throws Exception {

        LoginRequest loginRequest = new LoginRequest(testUsername, testPassword);

        mockMvc
                .perform(
                        post(loginPath)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsBytes(loginRequest))
                )
                .andExpect(status().isOk())
                .andDo(print());

    }

    @Test
    @DisplayName("fail by unregistered username")
    void failLoginByUsername() throws Exception {

        LoginRequest failPasswordLoginRequest = new LoginRequest(testFailUsername, testPassword);

        mockMvc
                .perform(
                        post(loginPath)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsBytes(failPasswordLoginRequest))
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @Test
    @DisplayName("fail by wrong password")
    void failLoginByPassword() throws Exception {

        LoginRequest failUsernameLoginRequest = new LoginRequest(testUsername, testFailPassword);

        mockMvc
                .perform(
                        post(loginPath)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsBytes(failUsernameLoginRequest))
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    static User createUser(PasswordEncoder passwordEncoder) {
        return User
                .builder()
                .name("테스트")
                .email(testUsername)
                .password(passwordEncoder.encode(testPassword))
                .profileImage("https://www.test.com/image/me")
                .howJoin("테스트를 위한 계정입니다.")
                .phone("01031157613")
                .genderType(MALE)
                .birth(LocalDate.now())
                .howJoin("테스트")
                .build();
    }

    @AfterAll
    static void deleteUser(@Autowired UserRepository userRepository){
        userRepository.deleteAllInBatch();
    }

}
