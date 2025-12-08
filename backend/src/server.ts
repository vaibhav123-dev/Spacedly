import app from './app';
import sequelize from './config/database';
import { startReminderCron } from './services/reminderCron.service';
import dotenv from 'dotenv';

dotenv.config();

// Validate critical environment variables
const validateEnvironment = () => {
  const requiredVars = [
    'DB_NAME',
    'DB_USERNAME',
    'DB_PASSWORD',
    'DB_HOST',
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',
  ];

  const emailVars = ['EMAIL_USER', 'EMAIL_PASS'];

  const missing = requiredVars.filter(varName => !process.env[varName]);
  const missingEmail = emailVars.filter(varName => !process.env[varName]);

  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing.join(', '));
    process.exit(1);
  }

  if (missingEmail.length > 0) {
    console.warn('⚠️  WARNING: Email variables not configured:', missingEmail.join(', '));
    console.warn('⚠️  Email features (reminders, OTP) will not work until configured.');
    console.warn('⚠️  For Gmail: Use App Password (not regular password)');
    console.warn('⚠️  Generate at: https://myaccount.google.com/apppasswords');
  } else {
    console.log('✅ Email configuration detected');
  }

  console.log('✅ Environment validation complete');
};

// Validate environment before starting
validateEnvironment();

sequelize
  .authenticate()
  .then(() => {
    console.log('✅ Database connected successfully');
    
    // Start reminder cron job
    startReminderCron();
    
    const PORT = Number(process.env.PORT) || 3000;
    const HOST = '0.0.0.0'; // Listen on all network interfaces for Railway
    
    app.listen(PORT, HOST, () => {
      console.log(`🚀 Server is running on ${HOST}:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('❌ Unable to connect to database', error);
    process.exit(1);
  });
export default app;
