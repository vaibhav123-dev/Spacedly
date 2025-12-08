// mailService.js
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

// Retry function with exponential backoff
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export const sendEmail = async (
  to: string, 
  subject: string, 
  html: string, 
  retries = 3
): Promise<void> => {
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
        // Add timeout configurations
        connectionTimeout: 10000, // 10 seconds
        greetingTimeout: 5000,    // 5 seconds
        socketTimeout: 15000,      // 15 seconds
        // Additional options for better reliability
        pool: true,
        maxConnections: 5,
        maxMessages: 10,
      });

      const mailOptions = {
        from: `"Spacedly" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html,
      };

      await transporter.sendMail(mailOptions);
      
      // If successful, close the transporter and return
      transporter.close();
      return;
      
    } catch (error: any) {
      lastError = error;
      console.error(`[Email] Attempt ${attempt}/${retries} failed:`, error.message);
      
      // If this isn't the last attempt, wait before retrying with exponential backoff
      if (attempt < retries) {
        const waitTime = Math.min(1000 * Math.pow(2, attempt - 1), 10000); // Max 10 seconds
        console.log(`[Email] Retrying in ${waitTime}ms...`);
        await delay(waitTime);
      }
    }
  }

  // If all retries failed, throw the last error
  console.error(`[Email] All ${retries} attempts failed for email to ${to}`);
  throw lastError || new Error('Failed to send email after all retries');
};
