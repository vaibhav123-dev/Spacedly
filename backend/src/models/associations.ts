import User from './user.model';
import Task from './task.model';
import TaskAttachment from './taskAttachment.model';
import Reminder from './reminder.model';

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

export { User, Task, TaskAttachment, Reminder };
