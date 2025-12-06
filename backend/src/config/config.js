const dotenv = require('dotenv');

dotenv.config();

const config = {
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  dialect: process.env.DB_DIALECT || 'mysql',
};

module.exports = {
  development: config,
  production: config,
  test: config,
};
