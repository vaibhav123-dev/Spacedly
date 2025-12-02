import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export interface TaskAttachment {
  id: string;
  name: string;
  size: number;
  type: string;
  url: string;
}

export interface Task {
  id: string;
  title: string;
  description: string;
  category: 'Study' | 'Work' | 'Personal';
  priority: 'Low' | 'Medium' | 'High';
  link?: string;
  attachments?: TaskAttachment[];
  createdAt: string;
  updatedAt: string;
}

interface TaskState {
  tasks: Task[];
  selectedTask: Task | null;
}

const initialState: TaskState = {
  tasks: [],
  selectedTask: null,
};

const taskSlice = createSlice({
  name: 'task',
  initialState,
  reducers: {
    setTasks: (state, action: PayloadAction<Task[]>) => {
      state.tasks = action.payload;
    },
    addTask: (state, action: PayloadAction<Task>) => {
      state.tasks.push(action.payload);
    },
    updateTask: (state, action: PayloadAction<Task>) => {
      const index = state.tasks.findIndex((t) => t.id === action.payload.id);
      if (index !== -1) {
        state.tasks[index] = action.payload;
      }
    },
    deleteTask: (state, action: PayloadAction<string>) => {
      state.tasks = state.tasks.filter((t) => t.id !== action.payload);
    },
    selectTask: (state, action: PayloadAction<Task | null>) => {
      state.selectedTask = action.payload;
    },
  },
});

export const { setTasks, addTask, updateTask, deleteTask, selectTask } = taskSlice.actions;
export default taskSlice.reducer;
