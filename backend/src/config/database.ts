import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';

dotenv.config();

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USERNAME,
  process.env.DB_PASSWORD,

  {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    dialect: 'mysql',
    logging: false,
    // Connection pool configuration
    pool: {
      max: 10, // Maximum number of connections in pool
      min: 2, // Minimum number of connections in pool
      acquire: 30000, // Maximum time (ms) to try to get connection before throwing error
      idle: 10000, // Maximum time (ms) that a connection can be idle before being released
      evict: 10000, // Time interval (ms) to run eviction to detect and remove idle connections
    },
    // Query timeouts
    dialectOptions: {
      connectTimeout: 60000, // MySQL connection timeout (60 seconds)
      acquireTimeout: 60000, // Timeout for acquiring connections from pool
      timeout: 60000, // Query timeout
    },
    // Connection retry configuration
    retry: {
      max: 3, // Maximum number of retry attempts
      match: [
        /ETIMEDOUT/,
        /EHOSTUNREACH/,
        /ECONNRESET/,
        /ECONNREFUSED/,
        /ETIMEDOUT/,
        /ESOCKETTIMEDOUT/,
        /EHOSTDOWN/,
        /EPIPE/,
        /EAI_AGAIN/,
        /SequelizeConnectionError/,
        /SequelizeConnectionRefusedError/,
        /SequelizeHostNotFoundError/,
        /SequelizeHostNotReachableError/,
        /SequelizeInvalidConnectionError/,
        /SequelizeConnectionTimedOutError/,
      ],
    },
  },
);

export default sequelize;
