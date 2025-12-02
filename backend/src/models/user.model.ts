import { Model, DataTypes } from 'sequelize';
import sequelize from '../config/database';

class User extends Model {
  public id!: string;
  public name!: string;
  public email!: string;
  public password!: string | null;
  public refresh_token!: string | null;
  public is_two_factor_enabled!: boolean;
  public two_factor_otp!: string | null;
  public two_factor_otp_expiry!: Date | null;
  public google_id!: string | null;
  public auth_provider!: 'local' | 'google';
  public reset_password_token!: string | null;
  public reset_password_expires!: Date | null;

  // timestamps!
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;
}

User.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    refresh_token: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    is_two_factor_enabled: {
      type: DataTypes.BOOLEAN,
      allowNull: true,
    },
    two_factor_otp: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    two_factor_otp_expiry: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    google_id: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true,
    },
    auth_provider: {
      type: DataTypes.ENUM('local', 'google'),
      allowNull: false,
      defaultValue: 'local',
    },
    reset_password_token: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true,
    },
    reset_password_expires: {
      type: DataTypes.DATE,
      allowNull: true,
    },
  },
  { modelName: 'User', timestamps: true, tableName: 'users', sequelize },
);

export default User;
