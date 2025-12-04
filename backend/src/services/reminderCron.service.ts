import cron from 'node-cron';
import { sendMorningReminders, sendHourBeforeReminders } from './reminderEmail.service';

export const startReminderCron = () => {
  // Run every hour at minute 0 (e.g., 1:00, 2:00, 3:00, etc.)
  cron.schedule('0 * * * *', async () => {
    try {
      const now = new Date();
      console.log(`\n[Cron] Running reminder checks at ${now.toISOString()}`);
      
      // Check if it's 5 AM IST (11:30 PM UTC previous day)
      // IST offset is +5:30, so 5 AM IST = 11:30 PM UTC
      const istOffset = 5.5 * 60 * 60 * 1000;
      const currentIST = new Date(now.getTime() + istOffset);
      const istHour = currentIST.getHours();
      
      // Send morning reminders at 5 AM IST
      if (istHour === 5) {
        console.log('[Cron] It\'s 5 AM IST - Sending morning reminders...');
        const morningCount = await sendMorningReminders();
        console.log(`[Cron] Morning reminders sent: ${morningCount}`);
      }
      
      // Send 1-hour-before reminders (runs every hour)
      console.log('[Cron] Checking for 1-hour-before reminders...');
      const hourBeforeCount = await sendHourBeforeReminders();
      console.log(`[Cron] 1-hour-before reminders sent: ${hourBeforeCount}`);
      
      console.log('[Cron] Reminder check completed\n');
    } catch (error) {
      console.error('[Cron Error]:', error);
    }
  });
  
  console.log('✅ Reminder cron job started - Running every hour');
  console.log('   - Morning emails: 5:00 AM IST (11:30 PM UTC)');
  console.log('   - 1-hour-before emails: Every hour\n');
};

// Manual trigger functions for testing
export const triggerMorningReminders = async () => {
  console.log('[Manual Trigger] Sending morning reminders...');
  const count = await sendMorningReminders();
  console.log(`[Manual Trigger] Morning reminders sent: ${count}`);
  return count;
};

export const triggerHourBeforeReminders = async () => {
  console.log('[Manual Trigger] Sending 1-hour-before reminders...');
  const count = await sendHourBeforeReminders();
  console.log(`[Manual Trigger] 1-hour-before reminders sent: ${count}`);
  return count;
};
