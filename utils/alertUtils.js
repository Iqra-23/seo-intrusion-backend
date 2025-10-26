import Alert from "../models/Alert.js";
import { transporter } from "../config/mailer.js";

// Suspicious keywords that trigger alerts
const SUSPICIOUS_KEYWORDS = [
  "critical", "vulnerability", "exploit", "sql injection", "xss", "csrf", 
  "malware", "virus", "hack", "breach", "attack", "intrusion", "malicious",
  "phishing", "backdoor", "trojan", "ransomware", "ddos", "brute force",
  "injection", "shell", "payload", "penetration", "unauthorized", "high",
  "medium", "low", "error", "warning", "suspicious"
];

// Check if log contains suspicious activity
export const checkSuspiciousActivity = async (log) => {
  try {
    console.log("🔍 Checking suspicious activity for log:", log.message);
    
    const message = log.message.toLowerCase();
    const keywords = log.keyword?.map(k => k.toLowerCase()) || [];
    
    console.log("Message:", message);
    console.log("Keywords:", keywords);
    console.log("Log Level:", log.level);

    // Check for suspicious keywords in message and keywords array
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => {
      const foundInMessage = message.includes(keyword);
      const foundInKeywords = keywords.some(k => k.includes(keyword) || keyword.includes(k));
      return foundInMessage || foundInKeywords;
    });

    console.log("Found Keywords:", foundKeywords);

    // Create alert if suspicious keywords found OR log level is suspicious/error/warning
    if (foundKeywords.length > 0 || log.level === "suspicious" || log.level === "error" || log.level === "warning") {
      
      // Determine severity based on keywords and log level
      let severity = "low";
      
      if (log.level === "suspicious" || foundKeywords.some(k => ["critical", "exploit", "breach", "attack"].includes(k))) {
        severity = "critical";
      } else if (foundKeywords.some(k => ["sql injection", "xss", "malware", "virus", "hack"].includes(k)) || log.level === "error") {
        severity = "high";
      } else if (foundKeywords.some(k => ["warning", "unauthorized", "intrusion"].includes(k))) {
        severity = "medium";
      }

      console.log("Alert Severity:", severity);

      // Create alert
      const alert = await Alert.create({
        logId: log._id,
        severity,
        title: `Suspicious Activity Detected: ${log.level.toUpperCase()}`,
        description: log.message,
        keywords: foundKeywords.length > 0 ? foundKeywords : [log.level]
      });

      console.log("✅ Alert created:", alert._id);

      // Send email notification for critical/high severity
      if (severity === "critical" || severity === "high") {
        await sendAlertEmail(alert, log);
      }

      return alert;
    }

    console.log("No alert created - no suspicious activity detected");
    return null;
  } catch (error) {
    console.error("❌ Check suspicious activity error:", error);
    return null;
  }
};

// Send alert email
const sendAlertEmail = async (alert, log) => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: adminEmail,
      subject: `🚨 ${alert.severity.toUpperCase()} Security Alert - SEO Intrusion Detector`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
          <div style="background-color: ${alert.severity === 'critical' ? '#dc2626' : '#ea580c'}; color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center;">
            <h1 style="margin: 0;">🚨 Security Alert</h1>
          </div>
          <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
            <h2 style="color: #dc2626; margin-top: 0;">${alert.title}</h2>
            
            <div style="background-color: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 20px 0;">
              <p style="margin: 0; font-weight: bold; color: #991b1b;">Severity: ${alert.severity.toUpperCase()}</p>
            </div>

            <h3 style="color: #374151;">Details:</h3>
            <ul style="color: #6b7280; line-height: 1.8;">
              <li><strong>Log Level:</strong> ${log.level}</li>
              <li><strong>Message:</strong> ${log.message}</li>
              <li><strong>Time:</strong> ${new Date(log.createdAt).toLocaleString()}</li>
              ${log.ipAddress ? `<li><strong>IP Address:</strong> ${log.ipAddress}</li>` : ''}
              ${log.url ? `<li><strong>URL:</strong> ${log.url}</li>` : ''}
              ${alert.keywords.length > 0 ? `<li><strong>Detected Keywords:</strong> ${alert.keywords.join(', ')}</li>` : ''}
            </ul>

            <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
              <p style="margin: 0; color: #92400e;">
                <strong>⚠️ Action Required:</strong> Please review this activity immediately in your dashboard.
              </p>
            </div>

            <a href="${process.env.FRONTEND_URL || 'http://localhost:5173'}/alerts" 
               style="display: inline-block; background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 10px; font-weight: bold;">
              View Alert
            </a>

            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
            
            <p style="color: #6b7280; font-size: 12px; line-height: 1.6; margin: 0;">
              This is an automated security alert from SEO Intrusion Detector.<br>
              © 2025 SEO Intrusion Detector. All rights reserved.
            </p>
          </div>
        </div>
      `,
      text: `
Security Alert - ${alert.severity.toUpperCase()}

${alert.title}

Details:
- Log Level: ${log.level}
- Message: ${log.message}
- Time: ${new Date(log.createdAt).toLocaleString()}
${log.ipAddress ? `- IP Address: ${log.ipAddress}` : ''}
${alert.keywords.length > 0 ? `- Keywords: ${alert.keywords.join(', ')}` : ''}

Please review this activity immediately in your dashboard.
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Alert email sent for ${alert.severity} severity alert`);
  } catch (error) {
    console.error("❌ Send alert email error:", error);
  }
};

// Check for patterns
export const detectPatterns = async (userId, eventType) => {
  // Pattern detection implementation
};

export default { checkSuspiciousActivity, detectPatterns };