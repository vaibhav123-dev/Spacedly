import { Op } from 'sequelize';
import Reminder from '../models/reminder.model';
import Task from '../models/task.model';
import User from '../models/user.model';
import { sendEmail } from '../utils/emailUtil';
import { morningReminderEmailTemplate, hourBeforeReminderEmailTemplate } from '../helpers/emailTemplates';
import * as notificationService from './notification.service';

// Convert UTC date to IST string for display
const formatTimeInIST = (utcDate: Date): string => {
  return utcDate.toLocaleString('en-IN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZone: 'Asia/Kolkata'
  });
};

export const sendMorningReminders = async () => {
  try {
    const now = new Date();
    
    // Calculate 5 AM IST in UTC (11:30 PM previous day UTC)
    const istOffset = 5.5 * 60 * 60 * 1000;
    const currentIST = new Date(now.getTime() + istOffset);
    
    // Get today's date in IST
    const todayIST = new Date(currentIST);
    todayIST.setHours(0, 0, 0, 0);
    
    // Get tomorrow's date in IST
    const tomorrowIST = new Date(todayIST);
    tomorrowIST.setDate(tomorrowIST.getDate() + 1);
    
    // Convert back to UTC for database query
    const todayUTC = new Date(todayIST.getTime() - istOffset);
    const tomorrowUTC = new Date(tomorrowIST.getTime() - istOffset);
    
    console.log(`[Morning Reminders] Checking for reminders scheduled today (IST)`);
    
    // Find all pending reminders scheduled for today that haven't received morning email
    const reminders = await Reminder.findAll({
      where: {
        status: 'pending',
        morningEmailSent: false,
        scheduledAt: {
          [Op.gte]: todayUTC,
          [Op.lt]: tomorrowUTC,
        },
      },
      include: [
        {
          model: Task,
          as: 'task',
          required: true,
        },
        {
          model: User,
          as: 'user',
          required: true,
        },
      ],
    });
    
    console.log(`[Morning Reminders] Found ${reminders.length} reminders to send`);
    
    for (const reminder of reminders) {
      try {
        const task = reminder.task as any;
        const user = reminder.user as any;
        
        const reminderTimeIST = formatTimeInIST(reminder.scheduledAt);
        
        const emailHtml = morningReminderEmailTemplate(
          user.name || user.email,
          task.title,
          task.description || 'No description provided',
          reminderTimeIST
        );
        
        await sendEmail(
          user.email,
          '🌅 Good Morning - Your Task Reminder',
          emailHtml
        );
        
        // Mark as sent
        await reminder.update({ morningEmailSent: true });
        
        // Create in-app notification
        await notificationService.createNotification({
          userId: user.id,
          type: 'reminder',
          title: '🌅 Good Morning Reminder',
          message: `Your task "${task.title}" is scheduled for ${reminderTimeIST}`,
          relatedTaskId: task.id,
        });
        
        console.log(`[Morning Email] Sent to ${user.email} for task: ${task.title}`);
      } catch (error) {
        console.error(`[Morning Email Error] Failed for reminder ${reminder.id}:`, error);
      }
    }
    
    return reminders.length;
  } catch (error) {
    console.error('[Morning Reminders Error]:', error);
    throw error;
  }
};

export const sendHourBeforeReminders = async () => {
  try {
    const now = new Date();
    
    // Calculate time 1 hour from now (with 5 min buffer on each side for the hourly cron)
    const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
    const bufferBefore = new Date(oneHourLater.getTime() - 5 * 60 * 1000);
    const bufferAfter = new Date(oneHourLater.getTime() + 5 * 60 * 1000);
    
    console.log(`[1-Hour Reminders] Checking for reminders between ${bufferBefore.toISOString()} and ${bufferAfter.toISOString()}`);
    
    // Find all pending reminders scheduled 1 hour from now that haven't received the 1-hour email
    const reminders = await Reminder.findAll({
      where: {
        status: 'pending',
        hourBeforeEmailSent: false,
        scheduledAt: {
          [Op.gte]: bufferBefore,
          [Op.lte]: bufferAfter,
        },
      },
      include: [
        {
          model: Task,
          as: 'task',
          required: true,
        },
        {
          model: User,
          as: 'user',
          required: true,
        },
      ],
    });
    
    console.log(`[1-Hour Reminders] Found ${reminders.length} reminders to send`);
    
    for (const reminder of reminders) {
      try {
        const task = reminder.task as any;
        const user = reminder.user as any;
        
        const reminderTimeIST = formatTimeInIST(reminder.scheduledAt);
        
        const emailHtml = hourBeforeReminderEmailTemplate(
          user.name || user.email,
          task.title,
          task.description || 'No description provided',
          reminderTimeIST
        );
        
        await sendEmail(
          user.email,
          '⏰ Task Starting in 1 Hour!',
          emailHtml
        );
        
        // Mark as sent
        await reminder.update({ hourBeforeEmailSent: true });
        
        // Create in-app notification
        await notificationService.createNotification({
          userId: user.id,
          type: 'upcoming',
          title: '⏰ Task Starting Soon',
          message: `Your task "${task.title}" starts in 1 hour at ${reminderTimeIST}`,
          relatedTaskId: task.id,
        });
        
        console.log(`[1-Hour Email] Sent to ${user.email} for task: ${task.title}`);
      } catch (error) {
        console.error(`[1-Hour Email Error] Failed for reminder ${reminder.id}:`, error);
      }
    }
    
    return reminders.length;
  } catch (error) {
    console.error('[1-Hour Reminders Error]:', error);
    throw error;
  }
};
