export const passwordResetTemplate = (resetUrl: string, userName: string) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body {
          font-family: Arial, sans-serif;
          line-height: 1.6;
          color: #333;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 30px;
          text-align: center;
          border-radius: 10px 10px 0 0;
        }
        .content {
          background: #f9fafb;
          padding: 30px;
          border-radius: 0 0 10px 10px;
        }
        .button {
          display: inline-block;
          padding: 12px 30px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          text-decoration: none;
          border-radius: 5px;
          margin: 20px 0;
          font-weight: bold;
        }
        .footer {
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #e5e7eb;
          font-size: 12px;
          color: #6b7280;
        }
        .warning {
          background: #fef3c7;
          border-left: 4px solid #f59e0b;
          padding: 15px;
          margin: 20px 0;
          border-radius: 5px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Spacedly</h1>
          <p>Password Reset Request</p>
        </div>
        <div class="content">
          <p>Hi ${userName},</p>
          
          <p>We received a request to reset your password for your Spacedly account. If you didn't make this request, you can safely ignore this email.</p>
          
          <p>To reset your password, click the button below:</p>
          
          <center>
            <a href="${resetUrl}" class="button">Reset Password</a>
          </center>
          
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break: break-all; color: #667eea;">${resetUrl}</p>
          
          <div class="warning">
            <strong>⚠️ Security Notice:</strong>
            <ul style="margin: 10px 0;">
              <li>This link will expire in 1 hour</li>
              <li>This link can only be used once</li>
              <li>Never share this link with anyone</li>
            </ul>
          </div>
          
          <div class="footer">
            <p>If you didn't request this password reset, please ignore this email or contact support if you have concerns.</p>
            <p>&copy; ${new Date().getFullYear()} Spacedly. All rights reserved.</p>
          </div>
        </div>
      </div>
    </body>
    </html>
  `;
};

export const morningReminderEmailTemplate = (userName: string, taskTitle: string, taskDescription: string, reminderTime: string) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; background: #f9fafb; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border-radius: 0 0 10px 10px; }
        .task-card { background: #f3f4f6; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0; border-radius: 5px; }
        .time-badge { display: inline-block; background: #fbbf24; color: #78350f; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🌅 Good Morning!</h1>
          <p>Your Task Reminder</p>
        </div>
        <div class="content">
          <p>Hi ${userName},</p>
          <p>You have a task scheduled for today:</p>
          
          <div class="task-card">
            <h2 style="margin-top: 0; color: #667eea;">${taskTitle}</h2>
            <p>${taskDescription}</p>
            <div class="time-badge">
              ⏰ Scheduled for ${reminderTime}
            </div>
          </div>
          
          <p>Have a productive day!</p>
          <p style="color: #6b7280; font-size: 14px; margin-top: 30px;">
            You'll receive another reminder 1 hour before the scheduled time.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
};

export const hourBeforeReminderEmailTemplate = (userName: string, taskTitle: string, taskDescription: string, reminderTime: string) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; background: #f9fafb; }
        .header { background: linear-gradient(135deg, #f59e0b 0%, #dc2626 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: white; padding: 30px; border-radius: 0 0 10px 10px; }
        .task-card { background: #fef3c7; padding: 20px; border-left: 4px solid #f59e0b; margin: 20px 0; border-radius: 5px; }
        .urgent-badge { display: inline-block; background: #dc2626; color: white; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>⏰ Task Starting Soon!</h1>
          <p>1 Hour Reminder</p>
        </div>
        <div class="content">
          <p>Hi ${userName},</p>
          <p><strong>Your task starts in 1 hour!</strong></p>
          
          <div class="task-card">
            <h2 style="margin-top: 0; color: #f59e0b;">${taskTitle}</h2>
            <p>${taskDescription}</p>
            <div class="urgent-badge">
              🔔 Starting at ${reminderTime}
            </div>
          </div>
          
          <p>Time to wrap up what you're doing and prepare for this task!</p>
        </div>
      </div>
    </body>
    </html>
  `;
};
