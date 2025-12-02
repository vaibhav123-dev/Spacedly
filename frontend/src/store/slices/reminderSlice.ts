import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export interface Reminder {
  id: string;
  taskId: string;
  scheduledAt: string;
  status: 'pending' | 'completed' | 'skipped';
  createdAt: string;
}

interface ReminderState {
  reminders: Reminder[];
}

const initialState: ReminderState = {
  reminders: [],
};

const reminderSlice = createSlice({
  name: 'reminder',
  initialState,
  reducers: {
    setReminders: (state, action: PayloadAction<Reminder[]>) => {
      state.reminders = action.payload;
    },
    addReminder: (state, action: PayloadAction<Reminder>) => {
      state.reminders.push(action.payload);
    },
    updateReminder: (state, action: PayloadAction<Reminder>) => {
      const index = state.reminders.findIndex((r) => r.id === action.payload.id);
      if (index !== -1) {
        state.reminders[index] = action.payload;
      }
    },
    deleteReminder: (state, action: PayloadAction<string>) => {
      state.reminders = state.reminders.filter((r) => r.id !== action.payload);
    },
  },
});

export const { setReminders, addReminder, updateReminder, deleteReminder } = reminderSlice.actions;
export default reminderSlice.reducer;
