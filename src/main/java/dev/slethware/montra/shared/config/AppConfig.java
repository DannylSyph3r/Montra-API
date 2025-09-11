package dev.slethware.montra.shared.config;

import dev.slethware.montra.shared.audit.ApplicationAuditor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Properties;

@Configuration
public class AppConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuditorAware<String> auditorAware() {
        return new ApplicationAuditor();
    }

    @Value("${server.mail.host}")
    private String mailHost;

    @Value("${server.mail.port}")
    private int mailPort;

    @Value("${server.mail.username}")
    private String mailUsername;

    @Value("${server.mail.password}")
    private String mailPassword;

    @Value("${monnify.api.key:''}")
    private String monnifyApiKey;

    @Value("${monnify.api.secret.key:''}")
    private String monnifySecretKey;

    @Bean
    public JavaMailSender customJavaMailSender(){
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        // Set your SMTP server properties
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);
        mailSender.setUsername(mailUsername);
        mailSender.setPassword(mailPassword);

        // Configure additional properties
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", "true");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory"); // Explicit SSL
        props.put("mail.smtp.ssl.trust", "*");
        props.put("mail.smtp.connectiontimeout", "30000"); // Timeout in milliseconds
        props.put("mail.smtp.timeout", "30000"); // Timeout in milliseconds
        props.put("mail.smtp.writetimeout", "30000"); // Timeout in milliseconds
        props.put("mail.debug", "true");

        return mailSender;
    }

//    @Bean
//    public WebClient.Builder webClientBuilder(){
//        return WebClient.builder();
//    }
}