'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('users', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
      },
      password: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      refresh_token: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      is_two_factor_enabled: {
        type: Sequelize.BOOLEAN,
        allowNull: true,
        defaultValue: false,
      },
      two_factor_otp: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      two_factor_otp_expiry: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      google_id: {
        type: Sequelize.STRING,
        allowNull: true,
        unique: true,
      },
      auth_provider: {
        type: Sequelize.ENUM('local', 'google'),
        allowNull: false,
        defaultValue: 'local',
      },
      reset_password_token: {
        type: Sequelize.STRING,
        allowNull: true,
        unique: true,
      },
      reset_password_expires: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
      },
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('users');
  },
};
