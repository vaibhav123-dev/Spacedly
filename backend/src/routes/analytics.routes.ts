import { Router } from 'express';
import * as analyticsController from '../controllers/analytics.controller';
import { authMiddleware } from '../middlewares/auth.middleware';

const router = Router();

router.use(authMiddleware);

router.get('/', analyticsController.getAnalytics);
router.get('/streaks', analyticsController.getStreaks);

export default router;
