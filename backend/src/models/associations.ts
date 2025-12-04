import User from './user.model';
import Task from './task.model';
import TaskAttachment from './taskAttachment.model';
import Reminder from './reminder.model';
import Notification from './notification.model';

// User <-> Task associations
User.hasMany(Task, { foreignKey: 'userId', as: 'tasks' });
Task.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// Task <-> TaskAttachment associations
Task.hasMany(TaskAttachment, { foreignKey: 'taskId', as: 'attachments' });
TaskAttachment.belongsTo(Task, { foreignKey: 'taskId', as: 'task' });

// Task <-> Reminder associations
Task.hasMany(Reminder, { foreignKey: 'taskId', as: 'reminders' });
Reminder.belongsTo(Task, { foreignKey: 'taskId', as: 'task' });

// User <-> Reminder associations
User.hasMany(Reminder, { foreignKey: 'userId', as: 'reminders' });
Reminder.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// User <-> Notification associations
User.hasMany(Notification, { foreignKey: 'userId', as: 'notifications' });
Notification.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// Task <-> Notification associations (optional relation)
Task.hasMany(Notification, { foreignKey: 'relatedTaskId', as: 'notifications' });
Notification.belongsTo(Task, { foreignKey: 'relatedTaskId', as: 'task' });

export { User, Task, TaskAttachment, Reminder, Notification };
