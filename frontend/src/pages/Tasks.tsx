import { useState, useEffect, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Plus, Edit, Trash2, Search, Calendar as CalendarIcon, X, Clock, Upload, File, FileText, Image as ImageIcon, Paperclip, Download } from 'lucide-react';
import { useGetTasksQuery, useCreateTaskMutation, useUpdateTaskMutation, useDeleteTaskMutation, useUploadAttachmentsMutation } from '@/store/api/taskApi';
import { useCreateReminderMutation, useGetTaskRemindersQuery, useUpdateReminderMutation, useDeleteReminderMutation } from '@/store/api/reminderApi';
import { Task, TaskAttachment } from '@/store/slices/taskSlice';
import { API_BASE_URL } from '@/config/app';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { Badge } from '@/components/ui/badge';
import { format } from 'date-fns';
import { cn } from '@/lib/utils';

interface ReminderInput {
  id?: string;
  date: Date | undefined;
  time: string;
}

interface FileWithPreview {
  file: File;
  preview: string;
  id: string;
}

// Dummy tasks for UI testing
const dummyTasks: Task[] = [
  {
    id: '1',
    title: 'Complete React Tutorial',
    description: 'Finish the advanced React hooks tutorial and practice with examples',
    category: 'Study',
    priority: 'High',
    link: 'https://react.dev/learn',
    attachments: [
      { id: 'a1', name: 'notes.pdf', size: 2048000, type: 'application/pdf', url: '' },
      { id: 'a2', name: 'diagram.png', size: 512000, type: 'image/png', url: '' }
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '2',
    title: 'Team Meeting Preparation',
    description: 'Prepare slides and agenda for the quarterly team meeting',
    category: 'Work',
    priority: 'Medium',
    link: 'https://docs.google.com/presentation',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '3',
    title: 'Grocery Shopping',
    description: 'Buy vegetables, fruits, and household items for the week',
    category: 'Personal',
    priority: 'Low',
    attachments: [
      { id: 'a3', name: 'shopping-list.txt', size: 1024, type: 'text/plain', url: '' }
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '4',
    title: 'Database Design Course',
    description: 'Complete the SQL fundamentals module and practice queries',
    category: 'Study',
    priority: 'High',
    link: 'https://www.coursera.org/learn/database-design',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '5',
    title: 'Project Code Review',
    description: 'Review pull requests from team members and provide feedback',
    category: 'Work',
    priority: 'High',
    attachments: [
      { id: 'a4', name: 'review-checklist.docx', size: 30720, type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', url: '' }
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '6',
    title: 'Workout Routine',
    description: 'Morning cardio and evening strength training session',
    category: 'Personal',
    priority: 'Medium',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '7',
    title: 'JavaScript Advanced Concepts',
    description: 'Study closures, promises, and async/await patterns in depth',
    category: 'Study',
    priority: 'Medium',
    attachments: [
      { id: 'a5', name: 'code-samples.js', size: 4096, type: 'text/javascript', url: '' },
      { id: 'a6', name: 'reference.pdf', size: 1536000, type: 'application/pdf', url: '' }
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '8',
    title: 'Client Presentation',
    description: 'Prepare and deliver product demo to potential client',
    category: 'Work',
    priority: 'High',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '9',
    title: 'Book Club Reading',
    description: 'Finish reading chapters 5-8 for next week discussion',
    category: 'Personal',
    priority: 'Low',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: '10',
    title: 'API Documentation',
    description: 'Write comprehensive API documentation for the new endpoints',
    category: 'Work',
    priority: 'Medium',
    attachments: [
      { id: 'a7', name: 'api-spec.yaml', size: 8192, type: 'text/yaml', url: '' }
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

const Tasks = () => {
  const { data: tasks, isLoading } = useGetTasksQuery();
  const [createTask] = useCreateTaskMutation();
  const [updateTask] = useUpdateTaskMutation();
  const [deleteTask] = useDeleteTaskMutation();
  const [uploadAttachments] = useUploadAttachmentsMutation();
  const [createReminder] = useCreateReminderMutation();
  const [updateReminder] = useUpdateReminderMutation();
  const [deleteReminder] = useDeleteReminderMutation();

  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingTask, setEditingTask] = useState<Task | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 6;
  
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: 'Study' as 'Study' | 'Work' | 'Personal',
    priority: 'Medium' as 'Low' | 'Medium' | 'High',
    link: '',
  });

  const [reminders, setReminders] = useState<ReminderInput[]>([]);
  const [existingReminderIds, setExistingReminderIds] = useState<string[]>([]);
  const [attachedFiles, setAttachedFiles] = useState<FileWithPreview[]>([]);
  const [existingAttachments, setExistingAttachments] = useState<TaskAttachment[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch existing reminders when editing a task
  const { data: taskReminders } = useGetTaskRemindersQuery(editingTask?.id || '', {
    skip: !editingTask?.id,
  });

  useEffect(() => {
    if (editingTask && taskReminders) {
      const existingReminders = taskReminders.map((reminder) => {
        const date = new Date(reminder.scheduledAt);
        return {
          id: reminder.id,
          date: date,
          time: format(date, 'HH:mm'),
        };
      });
      setReminders(existingReminders);
      setExistingReminderIds(taskReminders.map(r => r.id));
    }
  }, [editingTask, taskReminders]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      let taskId: string;

      if (editingTask) {
        await updateTask({ id: editingTask.id, ...formData }).unwrap();
        taskId = editingTask.id;
        toast.success('Task updated successfully');
      } else {
        const newTask = await createTask(formData).unwrap();
        taskId = newTask.id;
        toast.success('Task created successfully');
      }

      // Upload attachments if any
      if (attachedFiles.length > 0) {
        const filesToUpload = attachedFiles.map(f => f.file);
        await uploadAttachments({ taskId, files: filesToUpload }).unwrap();
        toast.success(`${attachedFiles.length} file(s) uploaded successfully`);
      }

      // Handle reminders
      if (reminders.length > 0) {
        // Create new reminders (those without ID)
        const newReminders = reminders?.filter(r => !r.id);
        
        for (const reminder of newReminders) {
          if (reminder.date && reminder.time) {
            const [hours, minutes] = reminder.time.split(':').map(Number);
            const scheduledDate = new Date(reminder.date);
            scheduledDate.setHours(hours, minutes, 0, 0);

            await createReminder({
              taskId,
              scheduledAt: scheduledDate.toISOString(),
              status: 'pending',
            }).unwrap();
          }
        }
        
        // Update existing reminders (those with ID)
        const existingReminders = reminders?.filter(r => r.id);
        
        for (const reminder of existingReminders) {
          if (reminder.date && reminder.time && reminder.id) {
            const [hours, minutes] = reminder.time.split(':').map(Number);
            const scheduledDate = new Date(reminder.date);
            scheduledDate.setHours(hours, minutes, 0, 0);

            await updateReminder({
              id: reminder.id,
              scheduledAt: scheduledDate.toISOString(),
              status: 'pending',
            }).unwrap();
          }
        }
        
        const totalUpdated = newReminders.length + existingReminders.length;
        if (totalUpdated > 0) {
          toast.success(`${totalUpdated} reminder(s) updated`);
        }
      }

      // Delete removed reminders
      if (editingTask) {
        const currentReminderIds = reminders?.filter(r => r.id).map(r => r.id!);
        const removedIds = existingReminderIds?.filter(id => !currentReminderIds.includes(id));
        
        for (const id of removedIds) {
          await deleteReminder(id).unwrap();
        }
      }

      setIsDialogOpen(false);
      resetForm();
    } catch (error: any) {
      toast.error(error?.data?.message || 'Operation failed');
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this task?')) {
      try {
        await deleteTask(id).unwrap();
        toast.success('Task deleted successfully');
      } catch (error: any) {
        toast.error(error?.data?.message || 'Failed to delete task');
      }
    }
  };

  const handleEdit = (task: Task) => {
    setEditingTask(task);
    setFormData({
      title: task.title,
      description: task.description,
      category: task.category,
      priority: task.priority,
      link: task.link || '',
    });
    if (task.attachments) {
      setExistingAttachments(task.attachments);
    }
    setIsDialogOpen(true);
  };

  const resetForm = () => {
    setEditingTask(null);
    setFormData({
      title: '',
      description: '',
      category: 'Study',
      priority: 'Medium',
      link: '',
    });
    setReminders([]);
    setExistingReminderIds([]);
    setAttachedFiles([]);
    setExistingAttachments([]);
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files) return;

    const newFiles: FileWithPreview[] = [];
    let filesProcessed = 0;
    
    const addFile = (fileData: FileWithPreview) => {
      newFiles.push(fileData);
      filesProcessed++;
      
      if (filesProcessed === files.length) {
        setAttachedFiles([...attachedFiles, ...newFiles]);
        toast.success(`${files.length} file(s) attached`);
        
        // Reset file input
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      }
    };
    
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      
      if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (e) => {
          const preview = e.target?.result as string;
          addFile({
            file,
            preview,
            id: Math.random().toString(36).substr(2, 9),
          });
        };
        reader.readAsDataURL(file);
      } else {
        addFile({
          file,
          preview: '',
          id: Math.random().toString(36).substr(2, 9),
        });
      }
    }
  };

  const removeFile = (fileId: string) => {
    setAttachedFiles(attachedFiles?.filter(f => f.id !== fileId));
    toast.info('File removed');
  };

  const removeExistingAttachment = (attachmentId: string) => {
    setExistingAttachments(existingAttachments?.filter(a => a.id !== attachmentId));
    toast.info('Attachment will be removed when you save');
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileIcon = (fileType: string) => {
    if (fileType?.startsWith('image/')) return <ImageIcon className="h-4 w-4" />;
    if (fileType?.includes('pdf')) return <FileText className="h-4 w-4" />;
    return <File className="h-4 w-4" />;
  };

  const addReminder = () => {
    setReminders([...reminders, { date: undefined, time: '12:00' }]);
  };

  const removeReminder = (index: number) => {
    setReminders(reminders?.filter((_, i) => i !== index));
  };

  const updateReminderField = (index: number, field: 'date' | 'time', value: Date | string | undefined) => {
    const newReminders = [...reminders];
    if (field === 'date') {
      newReminders[index].date = value as Date | undefined;
    } else {
      newReminders[index].time = value as string;
    }
    setReminders(newReminders);
  };

  // Use dummy tasks for testing, fallback to API data
  // API returns { tasks: [...] }, extract the array
  const allTasks = tasks?.tasks || dummyTasks;

  // Apply filters
  const filteredTasks = allTasks?.filter((task) => {
    const matchesSearch = task.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      task.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = categoryFilter === 'all' || task.category === categoryFilter;
    const matchesPriority = priorityFilter === 'all' || task.priority === priorityFilter;
    
    return matchesSearch && matchesCategory && matchesPriority;
  });

  // Calculate pagination
  const totalPages = Math.ceil(filteredTasks.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedTasks = filteredTasks.slice(startIndex, endIndex);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, categoryFilter, priorityFilter]);

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'High': return 'bg-destructive text-destructive-foreground';
      case 'Medium': return 'bg-warning text-warning-foreground';
      case 'Low': return 'bg-success text-success-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Study': return 'bg-primary text-primary-foreground';
      case 'Work': return 'bg-accent text-accent-foreground';
      case 'Personal': return 'bg-secondary text-secondary-foreground';
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Tasks</h1>
          <p className="text-muted-foreground">Manage your learning tasks</p>
        </div>
        
        <Dialog open={isDialogOpen} onOpenChange={(open) => {
          setIsDialogOpen(open);
          if (!open) resetForm();
        }}>
          <DialogTrigger asChild>
            <Button className="gradient-primary">
              <Plus className="mr-2 h-4 w-4" />
              New Task
            </Button>
          </DialogTrigger>
          <DialogContent className="max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{editingTask ? 'Edit Task' : 'Create New Task'}</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="title">Title</Label>
                <Input
                  id="title"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  rows={3}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="link">Link (Optional)</Label>
                <Input
                  id="link"
                  type="url"
                  placeholder="https://example.com"
                  value={formData.link}
                  onChange={(e) => setFormData({ ...formData, link: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="category">Category</Label>
                  <Select
                    value={formData.category}
                    onValueChange={(value: any) => setFormData({ ...formData, category: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Study">Study</SelectItem>
                      <SelectItem value="Work">Work</SelectItem>
                      <SelectItem value="Personal">Personal</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="priority">Priority</Label>
                  <Select
                    value={formData.priority}
                    onValueChange={(value: any) => setFormData({ ...formData, priority: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Low">Low</SelectItem>
                      <SelectItem value="Medium">Medium</SelectItem>
                      <SelectItem value="High">High</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Reminders Section */}
              <div className="space-y-3 rounded-lg border p-4">
                <div className="flex items-center justify-between">
                  <Label className="flex items-center gap-2 text-base">
                    <Clock className="h-4 w-4" />
                    Reminders
                  </Label>
                  <Button type="button" variant="outline" size="sm" onClick={addReminder}>
                    <Plus className="mr-1 h-3 w-3" />
                    Add Reminder
                  </Button>
                </div>

                {reminders.length === 0 && (
                  <p className="text-center text-sm text-muted-foreground py-4">
                    No reminders set. Click "Add Reminder" to schedule one.
                  </p>
                )}

                <div className="space-y-3">
                  {reminders.map((reminder, index) => (
                    <div key={index} className="space-y-3 rounded-md border p-3">
                      <div className="flex gap-2 items-start">
                        <div className="flex-1 space-y-3">
                          <div>
                            <Label className="text-xs mb-2 block">Date</Label>
                            <Popover>
                              <PopoverTrigger asChild>
                                <Button
                                  type="button"
                                  variant="outline"
                                  className={cn(
                                    "w-full justify-start text-left font-normal",
                                    !reminder.date && "text-muted-foreground"
                                  )}
                                >
                                  <CalendarIcon className="mr-2 h-4 w-4" />
                                  {reminder.date ? format(reminder.date, 'PPP') : <span>Pick a date</span>}
                                </Button>
                              </PopoverTrigger>
                              <PopoverContent className="w-auto p-0" align="start">
                                <Calendar
                                  mode="single"
                                  selected={reminder.date}
                                  onSelect={(date) => updateReminderField(index, 'date', date)}
                                  initialFocus
                                />
                              </PopoverContent>
                            </Popover>
                          </div>

                          <div>
                            <Label className="text-xs mb-2 block">Time</Label>
                            <Input
                              type="time"
                              value={reminder.time}
                              onChange={(e) => updateReminderField(index, 'time', e.target.value)}
                              className="w-full"
                            />
                          </div>

                          {reminder.date && reminder.time && (
                            <p className="text-xs text-muted-foreground">
                              Reminder: {format(reminder.date, 'MMM d, yyyy')} at {reminder.time}
                            </p>
                          )}
                        </div>

                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => removeReminder(index)}
                          className="h-8 w-8 text-destructive flex-shrink-0"
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* File Attachments Section */}
              <div className="space-y-3 rounded-lg border p-4">
                <div className="flex items-center justify-between">
                  <Label className="flex items-center gap-2 text-base">
                    <Paperclip className="h-4 w-4" />
                    Attachments
                  </Label>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <Upload className="mr-1 h-3 w-3" />
                    Upload Files
                  </Button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    onChange={handleFileSelect}
                    className="hidden"
                    accept="image/*,.pdf,.doc,.docx,.txt,.xls,.xlsx,.ppt,.pptx"
                  />
                </div>

                {existingAttachments.length === 0 && attachedFiles.length === 0 && (
                  <p className="text-center text-sm text-muted-foreground py-4">
                    No files attached. Click "Upload Files" to add attachments.
                  </p>
                )}

                {/* Existing Attachments */}
                {existingAttachments.length > 0 && (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Existing Files</Label>
                    {existingAttachments.map((attachment) => (
                      <div
                        key={attachment.id}
                        className="flex items-center gap-2 rounded-md border p-2"
                      >
                        <div className="flex h-8 w-8 items-center justify-center rounded bg-muted">
                          {getFileIcon(attachment.type)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{attachment.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {formatFileSize(attachment.size)}
                          </p>
                        </div>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => removeExistingAttachment(attachment.id)}
                          className="h-8 w-8 text-destructive"
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}

                {/* New Attachments */}
                {attachedFiles.length > 0 && (
                  <div className="space-y-2">
                    {existingAttachments.length > 0 && (
                      <Label className="text-xs text-muted-foreground">New Files</Label>
                    )}
                    {attachedFiles.map((fileItem) => (
                      <div
                        key={fileItem.id}
                        className="flex items-center gap-2 rounded-md border p-2"
                      >
                        {fileItem.preview ? (
                          <img
                            src={fileItem.preview}
                            alt={fileItem.file.name}
                            className="h-8 w-8 rounded object-cover"
                          />
                        ) : (
                          <div className="flex h-8 w-8 items-center justify-center rounded bg-muted">
                            {getFileIcon(fileItem.file.type)}
                          </div>
                        )}
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{fileItem.file.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {formatFileSize(fileItem.file.size)}
                          </p>
                        </div>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => removeFile(fileItem.id)}
                          className="h-8 w-8 text-destructive"
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}

                {(attachedFiles.length > 0 || existingAttachments.length > 0) && (
                  <p className="text-xs text-muted-foreground">
                    {attachedFiles.length + existingAttachments.length} file(s) total
                  </p>
                )}
              </div>

              <div className="flex gap-2">
                <Button type="submit" className="flex-1 gradient-primary">
                  {editingTask ? 'Update' : 'Create'}
                </Button>
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Cancel
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Search and Filters */}
      <div className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search tasks..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px]">
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Filter by category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                <SelectItem value="Study">Study</SelectItem>
                <SelectItem value="Work">Work</SelectItem>
                <SelectItem value="Personal">Personal</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex-1 min-w-[200px]">
            <Select value={priorityFilter} onValueChange={setPriorityFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Filter by priority" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Priorities</SelectItem>
                <SelectItem value="High">High Priority</SelectItem>
                <SelectItem value="Medium">Medium Priority</SelectItem>
                <SelectItem value="Low">Low Priority</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {(categoryFilter !== 'all' || priorityFilter !== 'all') && (
            <Button
              variant="outline"
              onClick={() => {
                setCategoryFilter('all');
                setPriorityFilter('all');
              }}
            >
              Clear Filters
            </Button>
          )}
        </div>

        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            Showing {paginatedTasks.length} of {filteredTasks.length} tasks
          </span>
        </div>
      </div>

      {/* Tasks Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {paginatedTasks.map((task, index) => (
          <motion.div
            key={task.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: index * 0.05 }}
          >
            <Card className="glass transition-smooth hover:shadow-glow h-[200px] flex flex-col">
              <CardHeader className="flex-none">
                <CardTitle className="flex items-start justify-between">
                  <span className="line-clamp-1 flex-1 pr-2">{task.title}</span>
                  <div className="flex gap-1 flex-shrink-0">
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => handleEdit(task)}
                      className="h-8 w-8"
                    >
                      <Edit className="h-4 w-4" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => handleDelete(task.id)}
                      className="h-8 w-8 text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent className="flex-1 flex flex-col justify-between">
                <div className="flex-1">
                  <p className="line-clamp-3 text-sm text-muted-foreground mb-2">
                    {task.description}
                  </p>
                  {task.link && (
                    <a
                      href={task.link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline flex items-center gap-1 mt-2"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <span className="line-clamp-1">{task.link}</span>
                      <svg className="h-3 w-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </a>
                  )}
                </div>
                <div className="flex items-center justify-between mt-auto">
                  <div className="flex gap-2">
                    <Badge className={getCategoryColor(task.category)}>
                      {task.category}
                    </Badge>
                    <Badge className={getPriorityColor(task.priority)}>
                      {task.priority}
                    </Badge>
                  </div>
                  {task.attachments && task.attachments.length > 0 && (
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs text-muted-foreground hover:text-primary"
                        >
                          <Paperclip className="h-3 w-3 mr-1" />
                          <span>{task.attachments.length}</span>
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-80" align="end">
                        <div className="space-y-2">
                          <h4 className="font-medium text-sm mb-3">Attachments</h4>
                          {task.attachments.map((attachment) => (
                            <div
                              key={attachment.id}
                              className="flex items-center gap-2 rounded-md border p-2 hover:bg-muted/50 transition-colors"
                            >
                              <div className="flex h-8 w-8 items-center justify-center rounded bg-muted flex-shrink-0">
                                {getFileIcon(attachment.type)}
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate">{attachment.name}</p>
                                <p className="text-xs text-muted-foreground">
                                  {formatFileSize(attachment.size)}
                                </p>
                              </div>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8 flex-shrink-0"
                                onClick={() => {
                                  // Check if URL is already a full URL (Cloudinary)
                                  const fileUrl = attachment.url.startsWith('http') 
                                    ? attachment.url 
                                    : `${API_BASE_URL.replace('/api', '')}${attachment.url}`;
                                  
                                  // Open file in new tab for preview or download
                                  window.open(fileUrl, '_blank');
                                  toast.success(`Opening ${attachment.name}`);
                                }}
                              >
                                <Download className="h-4 w-4" />
                              </Button>
                            </div>
                          ))}
                        </div>
                      </PopoverContent>
                    </Popover>
                  )}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {filteredTasks.length === 0 && (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          <p>No tasks found. Create your first task to get started!</p>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage(currentPage - 1)}
            disabled={currentPage === 1}
          >
            Previous
          </Button>
          
          <div className="flex items-center gap-1">
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
              <Button
                key={page}
                variant={currentPage === page ? 'default' : 'outline'}
                size="sm"
                onClick={() => setCurrentPage(page)}
                className={cn(
                  'min-w-[40px]',
                  currentPage === page && 'gradient-primary'
                )}
              >
                {page}
              </Button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage(currentPage + 1)}
            disabled={currentPage === totalPages}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
};

export default Tasks;
