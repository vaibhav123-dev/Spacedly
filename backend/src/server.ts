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
    
    app.listen(process.env.PORT, () => {
      console.log(`Server is running at port ${process.env.PORT}`);
    });
  })
  .catch((error) => {
    console.log('Unable to connect to database', error);
  });
export default app;
