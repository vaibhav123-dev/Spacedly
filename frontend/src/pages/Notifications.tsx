import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useGetNotificationsQuery, useMarkAsReadMutation } from '@/store/api/notificationApi';
import { Bell, Clock, AlertCircle, CheckCircle2 } from 'lucide-react';
import { motion } from 'framer-motion';
import { toast } from 'sonner';

const Notifications = () => {
  const { data: notifications, isLoading } = useGetNotificationsQuery();
  const [markAsRead] = useMarkAsReadMutation();

  const handleMarkAsRead = async (id: string) => {
    try {
      await markAsRead(id).unwrap();
      toast.success('Notification marked as read');
    } catch (error) {
      toast.error('Failed to mark notification as read');
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'overdue':
        return <AlertCircle className="h-5 w-5 text-destructive" />;
      case 'upcoming':
        return <Clock className="h-5 w-5 text-warning" />;
      case 'reminder':
        return <Bell className="h-5 w-5 text-primary" />;
      default:
        return <Bell className="h-5 w-5" />;
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <Bell className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Notifications</h1>
          <p className="text-muted-foreground">Stay updated with your reminders</p>
        </div>
      </div>

      <div className="space-y-3">
        {notifications?.map((notification, index) => (
          <motion.div
            key={notification.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: index * 0.05 }}
          >
            <Card className={`glass transition-smooth hover:shadow-md ${!notification.isRead ? 'border-l-4 border-l-primary' : ''}`}>
              <CardContent className="flex items-start gap-4 p-4">
                <div className="rounded-full bg-muted p-2">
                  {getIcon(notification.type)}
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold">{notification.title}</h3>
                  <p className="text-sm text-muted-foreground">{notification.message}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{formatDate(notification.createdAt)}</p>
                </div>
                {!notification.isRead && (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleMarkAsRead(notification.id)}
                    className="shrink-0"
                  >
                    <CheckCircle2 className="h-4 w-4" />
                  </Button>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {!notifications || notifications.length === 0 && (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          <p>No notifications yet.</p>
        </div>
      )}
    </div>
  );
};

export default Notifications;
