import app from './app';
import sequelize from './config/database';
import { startReminderCron } from './services/reminderCron.service';
import dotenv from 'dotenv';

dotenv.config();

sequelize
  .authenticate()
  .then(() => {
    console.log('Database connected successfully');
    
    // Start reminder cron job
    startReminderCron();
    
    const PORT = Number(process.env.PORT) || 3000;
    const HOST = '0.0.0.0'; // Listen on all network interfaces for Railway
    
    app.listen(PORT, HOST, () => {
      console.log(`Server is running on ${HOST}:${PORT}`);
    });
  })
  .catch((error) => {
    console.log('Unable to connect to database', error);
  });
export default app;
