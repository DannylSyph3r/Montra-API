package dev.slethware.montra.email;

public interface EmailService {

    // Base email methods
    void sendEmail(String toEmail, String subject, String htmlContent);
    void sendEmailWithAttachment(String toEmail, String subject, String htmlContent, String attachmentPath);

    // Authentication emails
    void sendEmailVerification(String toEmail, String token);
    void sendPasswordReset(String toEmail, String token);
    void sendAdminInvitation(String toEmail, String tempPassword);

    // Notification emails
    void sendWelcomeEmail(String toEmail, String firstName);
    void sendPinSetupConfirmation(String toEmail, String firstName);
    void sendAccountSetupComplete(String toEmail, String firstName);
}
