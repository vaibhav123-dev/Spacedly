import Notification from '../models/notification.model';
import Task from '../models/task.model';
import ApiError from '../utils/apiError';
import HTTP_STATUS from '../constants';

interface CreateNotificationData {
  userId: string;
  type: 'overdue' | 'upcoming' | 'reminder' | 'general';
  title: string;
  message: string;
  relatedTaskId?: string;
}

export const createNotification = async (data: CreateNotificationData) => {
  try {
    const notification = await Notification.create(data);
    return notification;
  } catch (error) {
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to create notification');
  }
};

export const getUserNotifications = async (userId: string) => {
  try {
    const notifications = await Notification.findAll({
      where: { userId },
      include: [
        {
          model: Task,
          as: 'task',
          attributes: ['id', 'title'],
        },
      ],
      order: [['createdAt', 'DESC']],
    });
    return notifications;
  } catch (error) {
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to fetch notifications');
  }
};

export const getUnreadCount = async (userId: string) => {
  try {
    const count = await Notification.count({
      where: {
        userId,
        isRead: false,
      },
    });
    return count;
  } catch (error) {
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to fetch unread count');
  }
};

export const markAsRead = async (notificationId: string, userId: string) => {
  try {
    const notification = await Notification.findOne({
      where: { id: notificationId, userId },
    });

    if (!notification) {
      throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Notification not found');
    }

    notification.isRead = true;
    await notification.save();

    return notification;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to mark notification as read');
  }
};

export const markAllAsRead = async (userId: string) => {
  try {
    await Notification.update(
      { isRead: true },
      { where: { userId, isRead: false } }
    );
    return { message: 'All notifications marked as read' };
  } catch (error) {
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to mark all notifications as read');
  }
};

export const deleteNotification = async (notificationId: string, userId: string) => {
  try {
    const notification = await Notification.findOne({
      where: { id: notificationId, userId },
    });

    if (!notification) {
      throw new ApiError(HTTP_STATUS.NOT_FOUND, 'Notification not found');
    }

    await notification.destroy();
    return { message: 'Notification deleted successfully' };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Failed to delete notification');
  }
};
