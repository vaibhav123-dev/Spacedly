import { Model, DataTypes } from 'sequelize';
import sequelize from '../config/database';

class Reminder extends Model {
  public id!: string;
  public taskId!: string;
  public userId!: string;
  public scheduledAt!: Date;
  public status!: 'pending' | 'completed' | 'skipped';
  public morningEmailSent!: boolean;
  public hourBeforeEmailSent!: boolean;

  // associations
  public task?: any;
  public user?: any;

  // timestamp
  public readonly createdAt!: Date;
}

Reminder.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    taskId: {
      type: DataTypes.UUID,
      allowNull: false,
      field: 'task_id',
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      field: 'user_id',
    },
    scheduledAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'scheduled_at',
    },
    status: {
      type: DataTypes.ENUM('pending', 'completed', 'skipped'),
      allowNull: false,
      defaultValue: 'pending',
    },
    morningEmailSent: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'morning_email_sent',
    },
    hourBeforeEmailSent: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'hour_before_email_sent',
    },
  },
  {
    sequelize,
    modelName: 'Reminder',
    tableName: 'reminders',
    timestamps: true,
    underscored: true,
    createdAt: 'created_at',
    updatedAt: false,
  }
);

export default Reminder;
