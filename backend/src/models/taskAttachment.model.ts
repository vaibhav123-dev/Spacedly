import { Model, DataTypes } from 'sequelize';
import sequelize from '../config/database';

class TaskAttachment extends Model {
  public id!: string;
  public taskId!: string;
  public fileName!: string;
  public originalName!: string;
  public fileSize!: number;
  public fileType!: string;
  public fileUrl!: string;

  // timestamp
  public readonly createdAt!: Date;
}

TaskAttachment.init(
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
    fileName: {
      type: DataTypes.STRING,
      allowNull: false,
      field: 'file_name',
    },
    originalName: {
      type: DataTypes.STRING,
      allowNull: false,
      field: 'original_name',
    },
    fileSize: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'file_size',
    },
    fileType: {
      type: DataTypes.STRING,
      allowNull: false,
      field: 'file_type',
    },
    fileUrl: {
      type: DataTypes.STRING,
      allowNull: false,
      field: 'file_url',
    },
  },
  {
    sequelize,
    modelName: 'TaskAttachment',
    tableName: 'task_attachments',
    timestamps: true,
    underscored: true,
    createdAt: 'created_at',
    updatedAt: false,
  }
);

export default TaskAttachment;
