import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useGetRemindersQuery } from '@/store/api/reminderApi';
import { useGetTasksQuery } from '@/store/api/taskApi';
import { Calendar, Clock, ListTodo } from 'lucide-react';
import { motion } from 'framer-motion';
import FullCalendar from '@fullcalendar/react';
import dayGridPlugin from '@fullcalendar/daygrid';
import timeGridPlugin from '@fullcalendar/timegrid';
import interactionPlugin from '@fullcalendar/interaction';
import { EventClickArg } from '@fullcalendar/core';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface EventDetails {
  type: 'task' | 'reminder';
  id: string;
  title: string;
  description?: string;
  date: string;
  category?: string;
  priority?: string;
  status?: string;
}


const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'hsl(var(--success))';
      case 'skipped': return 'hsl(var(--muted))';
      case 'pending': return 'hsl(var(--warning))';
      default: return 'hsl(var(--muted))';
    }
};

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'High': return 'hsl(var(--destructive))';
      case 'Medium': return 'hsl(var(--warning))';
      case 'Low': return 'hsl(var(--success))';
      default: return 'hsl(var(--muted))';
    }
  };


const CalendarPage = () => {
  const { data: reminders, isLoading: remindersLoading } = useGetRemindersQuery();
  const { data: tasks, isLoading: tasksLoading } = useGetTasksQuery();
  const [selectedEvent, setSelectedEvent] = useState<EventDetails | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  const isLoading = remindersLoading || tasksLoading;

  const calendarEvents = useMemo(() => {
    const events = [];

    // Add tasks as events (using createdAt date)
    if (tasks) {
      tasks?.tasks.forEach((task) => {
        events.push({
          id: `task-${task.id}`,
          title: task.title,
          start: task.createdAt,
          backgroundColor: getPriorityColor(task.priority),
          borderColor: getPriorityColor(task.priority),
          extendedProps: {
            type: 'task',
            taskId: task.id,
            description: task.description,
            category: task.category,
            priority: task.priority,
          },
        });
      });
    }

    // Add reminders as events
    if (reminders?.reminders) {
      reminders.reminders.forEach((reminder) => {
        events.push({
          id: `reminder-${reminder.id}`,
          title: `Reminder`,
          start: reminder.scheduledAt,
          backgroundColor: getStatusColor(reminder.status),
          borderColor: getStatusColor(reminder.status),
          extendedProps: {
            type: 'reminder',
            reminderId: reminder.id,
            taskId: reminder.taskId,
            status: reminder.status,
          },
        });
      });
    }

    return events;
  }, [tasks, reminders]);

 

  const handleEventClick = (clickInfo: EventClickArg) => {
    const { event } = clickInfo;
    const { extendedProps } = event;
    
    if (extendedProps.type === 'task') {
      const task = tasks?.tasks.find(t => t.id === extendedProps.taskId);
      if (task) {
        setSelectedEvent({
          type: 'task',
          id: task.id,
          title: task.title,
          description: task.description,
          date: task.createdAt,
          category: task.category,
          priority: task.priority,
        });
        setDialogOpen(true);
      }
    } else if (extendedProps.type === 'reminder') {
      const reminder = reminders?.reminders?.find(r => r.id === extendedProps.reminderId);
      const task = tasks?.tasks.find(t => t.id === extendedProps.taskId);
      if (reminder) {
        setSelectedEvent({
          type: 'reminder',
          id: reminder.id,
          title: task ? `Reminder: ${task.title}` : 'Reminder',
          description: task?.description,
          date: reminder.scheduledAt,
          status: reminder.status,
        });
        setDialogOpen(true);
      }
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
      weekday: 'long',
      year: 'numeric', 
      month: 'long', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority) {
      case 'High': return 'bg-destructive text-destructive-foreground';
      case 'Medium': return 'bg-warning text-warning-foreground';
      case 'Low': return 'bg-success text-success-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-success text-success-foreground';
      case 'skipped': return 'bg-muted text-muted-foreground';
      case 'pending': return 'bg-warning text-warning-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
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
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <Calendar className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold">Calendar</h1>
            <p className="text-muted-foreground">View and manage your tasks and reminders</p>
          </div>
        </div>
        <div className="flex gap-2">
          <div className="flex items-center gap-2 rounded-lg bg-card p-2 px-4 text-sm">
            <div className="h-3 w-3 rounded-full bg-success"></div>
            <span className="text-muted-foreground">Low Priority / Completed</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-card p-2 px-4 text-sm">
            <div className="h-3 w-3 rounded-full bg-warning"></div>
            <span className="text-muted-foreground">Medium / Pending</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-card p-2 px-4 text-sm">
            <div className="h-3 w-3 rounded-full bg-destructive"></div>
            <span className="text-muted-foreground">High Priority</span>
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1 }}
      >
        <Card className="glass overflow-hidden">
          <CardContent className="p-6">
            <div className="calendar-wrapper">
              <FullCalendar
                plugins={[dayGridPlugin, timeGridPlugin, interactionPlugin]}
                initialView="dayGridMonth"
                headerToolbar={{
                  left: 'prev,next today',
                  center: 'title',
                  right: 'dayGridMonth,timeGridWeek,timeGridDay'
                }}
                events={calendarEvents}
                eventClick={handleEventClick}
                height="auto"
                editable={false}
                selectable={true}
                selectMirror={true}
                dayMaxEvents={true}
                weekends={true}
                eventDisplay="block"
                eventTimeFormat={{
                  hour: '2-digit',
                  minute: '2-digit',
                  meridiem: 'short'
                }}
              />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <div className="grid gap-4 md:grid-cols-2">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <Card className="glass">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ListTodo className="h-5 w-5 text-primary" />
                Recent Tasks
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {tasks?.tasks.slice(0, 5).map((task) => (
                  <div key={task.id} className="flex items-center justify-between rounded-lg border p-3">
                    <div className="flex-1">
                      <p className="font-medium">{task.title}</p>
                      <p className="text-sm text-muted-foreground">{task.category}</p>
                    </div>
                    <Badge className={getPriorityBadgeClass(task.priority)}>
                      {task.priority}
                    </Badge>
                  </div>
                ))}
                {(!tasks || tasks.tasks.length === 0) && (
                  <p className="text-center text-sm text-muted-foreground">No tasks yet</p>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <Card className="glass">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-primary" />
                Upcoming Reminders
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {reminders?.reminders?.slice(0, 5).map((reminder) => {
                  const task = tasks?.tasks.find(t => t.id === reminder.taskId);
                  return (
                    <div key={reminder.id} className="flex items-center justify-between rounded-lg border p-3">
                      <div className="flex-1">
                        <p className="font-medium">{task?.title || 'Unknown Task'}</p>
                        <p className="text-sm text-muted-foreground">
                          {new Date(reminder.scheduledAt).toLocaleDateString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                      </div>
                      <Badge className={getStatusBadgeClass(reminder.status)}>
                        {reminder.status}
                      </Badge>
                    </div>
                  );
                })}
                {(!reminders?.reminders || reminders.reminders.length === 0) && (
                  <p className="text-center text-sm text-muted-foreground">No reminders scheduled</p>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedEvent?.type === 'task' ? (
                <ListTodo className="h-5 w-5 text-primary" />
              ) : (
                <Clock className="h-5 w-5 text-primary" />
              )}
              {selectedEvent?.title}
            </DialogTitle>
            <DialogDescription>
              {formatDate(selectedEvent?.date || '')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {selectedEvent?.description && (
              <div>
                <h4 className="mb-2 font-medium">Description</h4>
                <p className="text-sm text-muted-foreground">{selectedEvent.description}</p>
              </div>
            )}
            <div className="flex gap-4">
              {selectedEvent?.category && (
                <div>
                  <h4 className="mb-2 font-medium">Category</h4>
                  <Badge variant="outline">{selectedEvent.category}</Badge>
                </div>
              )}
              {selectedEvent?.priority && (
                <div>
                  <h4 className="mb-2 font-medium">Priority</h4>
                  <Badge className={getPriorityBadgeClass(selectedEvent.priority)}>
                    {selectedEvent.priority}
                  </Badge>
                </div>
              )}
              {selectedEvent?.status && (
                <div>
                  <h4 className="mb-2 font-medium">Status</h4>
                  <Badge className={getStatusBadgeClass(selectedEvent.status)}>
                    {selectedEvent.status}
                  </Badge>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default CalendarPage;
