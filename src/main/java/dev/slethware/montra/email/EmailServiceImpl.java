package dev.slethware.montra.email;

import dev.slethware.montra.shared.exception.InternalServerException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.Date;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;

    @Value("${montra.email.from}")
    private String fromEmail;

    @Value("${montra.frontend.url}")
    private String frontendUrl;

    @Override
    @Async
    public void sendEmail(String toEmail, String subject, String htmlContent) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage, true);

            messageHelper.setFrom(fromEmail);
            messageHelper.setTo(toEmail);
            messageHelper.setSubject(subject);
            messageHelper.setText(htmlContent, true);
            messageHelper.setSentDate(new Date());

            javaMailSender.send(mimeMessage);
            log.info("Email sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send email to: {} - Error: {}", toEmail, e.getMessage(), e);
            throw new InternalServerException("Failed to send email", e);
        }
    }

    @Override
    @Async
    public void sendEmailWithAttachment(String toEmail, String subject, String htmlContent, String attachmentPath) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage, true);

            messageHelper.setFrom(fromEmail);
            messageHelper.setTo(toEmail);
            messageHelper.setSubject(subject);
            messageHelper.setText(htmlContent, true);
            messageHelper.setSentDate(new Date());

            FileSystemResource attachment = new FileSystemResource(new File(attachmentPath));
            messageHelper.addAttachment(attachment.getFilename(), attachment);

            javaMailSender.send(mimeMessage);
            log.info("Email with attachment sent successfully to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send email with attachment to: {} - Error: {}", toEmail, e.getMessage(), e);
            throw new InternalServerException("Failed to send email with attachment", e);
        }
    }

    @Override
    public void sendEmailVerification(String toEmail, String token) {
        String verificationUrl = frontendUrl + "/verify-email?email=" + toEmail + "&token=" + token;

        String subject = "Verify Your Montra Account";
        String htmlContent = buildEmailVerificationTemplate(verificationUrl);

        sendEmail(toEmail, subject, htmlContent);
    }

    @Override
    public void sendPasswordReset(String toEmail, String token) {
        String resetUrl = frontendUrl + "/reset-password?email=" + toEmail + "&token=" + token;

        String subject = "Reset Your Montra Password";
        String htmlContent = buildPasswordResetTemplate(resetUrl);

        sendEmail(toEmail, subject, htmlContent);
    }

    @Override
    public void sendAdminInvitation(String toEmail, String tempPassword) {
        String loginUrl = frontendUrl + "/admin/login";

        String subject = "Invitation to Montra Admin Portal";
        String htmlContent = buildAdminInvitationTemplate(toEmail, tempPassword, loginUrl);

        sendEmail(toEmail, subject, htmlContent);
    }

    @Override
    public void sendWelcomeEmail(String toEmail, String firstName) {
        String subject = "Welcome to Montra!";
        String htmlContent = buildWelcomeTemplate(firstName);

        sendEmail(toEmail, subject, htmlContent);
    }

    @Override
    public void sendPinSetupConfirmation(String toEmail, String firstName) {
        String subject = "PIN Setup Successful";
        String htmlContent = buildPinSetupConfirmationTemplate(firstName);

        sendEmail(toEmail, subject, htmlContent);
    }

    @Override
    public void sendAccountSetupComplete(String toEmail, String firstName) {
        String subject = "Account Setup Complete";
        String htmlContent = buildAccountSetupCompleteTemplate(firstName);

        sendEmail(toEmail, subject, htmlContent);
    }

    // Email template builders
    private String buildEmailVerificationTemplate(String verificationUrl) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Verify Your Email</h1>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Thank you for signing up with Montra! Please verify your email address to complete your registration.
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="%s" style="background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                            Verify Email Address
                        </a>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        If you didn't create an account with Montra, please ignore this email.
                    </p>
                    
                    <p style="font-size: 14px; color: #666;">
                        This verification link will expire in 24 hours.
                    </p>
                </div>
            </body>
            </html>
            """.formatted(verificationUrl);
    }

    private String buildPasswordResetTemplate(String resetUrl) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Your Password</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Reset Your Password</h1>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        We received a request to reset your password. Click the button below to set a new password.
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="%s" style="background: #f5576c; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        If you didn't request a password reset, please ignore this email.
                    </p>
                    
                    <p style="font-size: 14px; color: #666;">
                        This reset link will expire in 30 minutes.
                    </p>
                </div>
            </body>
            </html>
            """.formatted(resetUrl);
    }

    private String buildAdminInvitationTemplate(String email, String tempPassword, String loginUrl) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Admin Invitation</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Admin Invitation</h1>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        You have been invited to join the Montra Admin Portal.
                    </p>
                    
                    <div style="background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Email:</strong> %s</p>
                        <p style="margin: 5px 0;"><strong>Temporary Password:</strong> %s</p>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="%s" style="background: #4facfe; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                            Access Admin Portal
                        </a>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        Please change your password after your first login.
                    </p>
                </div>
            </body>
            </html>
            """.formatted(email, tempPassword, loginUrl);
    }

    private String buildWelcomeTemplate(String firstName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Welcome to Montra</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to Montra!</h1>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Hi %s,
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Welcome to Montra - your personal financial transaction management companion! 
                        We're excited to help you take control of your finances.
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        To get started, please set up your 4-digit PIN for quick and secure access to your account.
                    </p>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        Thank you for choosing Montra!
                    </p>
                </div>
            </body>
            </html>
            """.formatted(firstName);
    }

    private String buildPinSetupConfirmationTemplate(String firstName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>PIN Setup Successful</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">PIN Setup Successful</h1>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Hi %s,
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Great! You've successfully set up your 4-digit PIN. You can now use this PIN for quick 
                        access to your Montra account on your mobile device.
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        For security reasons, you'll still need to use your full email and password for certain 
                        sensitive operations.
                    </p>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        Keep your PIN secure and never share it with anyone.
                    </p>
                </div>
            </body>
            </html>
            """.formatted(firstName);
    }

    private String buildAccountSetupCompleteTemplate(String firstName) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Account Setup Complete</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">Account Setup Complete!</h1>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Hi %s,
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Congratulations! Your Montra account is now fully set up and ready to use.
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        You can now start tracking your financial transactions, managing your expenses, 
                        and gaining insights into your spending patterns.
                    </p>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        Happy tracking!
                    </p>
                </div>
            </body>
            </html>
            """.formatted(firstName);
    }
}