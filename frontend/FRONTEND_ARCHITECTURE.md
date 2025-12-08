# Spacedly Frontend Architecture Guide

## 📚 Table of Contents

1. [Technology Stack](#technology-stack)
2. [Project Structure](#project-structure)
3. [State Management Architecture](#state-management-architecture)
4. [API Management with RTK Query](#api-management-with-rtk-query)
5. [Caching Strategy](#caching-strategy)
6. [Authentication Flow](#authentication-flow)
7. [Component Architecture](#component-architecture)
8. [Routing & Navigation](#routing--navigation)
9. [Development Workflow](#development-workflow)
10. [Best Practices](#best-practices)

---

## 🛠 Technology Stack

### Core Technologies
- **React 18.3** - UI Library with latest features (Concurrent Mode, Automatic Batching)
- **TypeScript 5.8** - Type safety and better developer experience
- **Vite 5.4** - Lightning-fast build tool and dev server
- **React Router 6.30** - Client-side routing

### State Management & Data Fetching
- **Redux Toolkit 2.11** - Simplified Redux with built-in best practices
- **RTK Query** - Powerful data fetching and caching (built into Redux Toolkit)
- **React Query (TanStack Query) 5.83** - Additional async state management

### UI Framework & Styling
- **Tailwind CSS 3.4** - Utility-first CSS framework
- **shadcn/ui** - High-quality, accessible component library built on Radix UI
- **Radix UI** - Unstyled, accessible UI primitives
- **Framer Motion 12.23** - Animation library
- **Lucide React** - Icon library

### Form Management
- **React Hook Form 7.61** - Performant form library with minimal re-renders
- **Zod 3.25** - TypeScript-first schema validation

### Additional Libraries
- **Axios 1.13** - HTTP client with interceptors
- **FullCalendar 6.1** - Calendar component
- **Recharts 2.15** - Chart library
- **date-fns 3.6** - Date utility library
- **js-cookie 3.0** - Cookie management

---

## 📁 Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── ui/             # shadcn/ui components (40+ components)
│   │   ├── AppSidebar.tsx  # Main navigation sidebar
│   │   ├── ProtectedRoute.tsx  # Route guard component
│   │   └── ThemeToggle.tsx # Dark/light mode toggle
│   │
│   ├── pages/              # Route-level components
│   │   ├── Dashboard.tsx   # Main dashboard
│   │   ├── Tasks.tsx       # Task management
│   │   ├── Analytics.tsx   # Analytics & charts
│   │   ├── CalendarPage.tsx # Calendar view
│   │   ├── Login.tsx       # Authentication
│   │   └── ...
│   │
│   ├── store/              # Redux store configuration
│   │   ├── store.ts        # Main store setup
│   │   ├── hooks.ts        # Typed Redux hooks
│   │   ├── api/            # RTK Query API slices
│   │   │   ├── authApi.ts
│   │   │   ├── taskApi.ts
│   │   │   ├── reminderApi.ts
│   │   │   ├── analyticsApi.ts
│   │   │   └── notificationApi.ts
│   │   └── slices/         # Redux state slices
│   │       ├── authSlice.ts
│   │       ├── taskSlice.ts
│   │       ├── analyticsSlice.ts
│   │       └── uiSlice.ts
│   │
│   ├── services/           # External service configurations
│   │   └── axios.ts        # Axios instance with interceptors
│   │
│   ├── layouts/            # Layout components
│   │   └── AppLayout.tsx   # Main app layout wrapper
│   │
│   ├── config/             # Configuration files
│   │   └── app.ts          # App-wide constants
│   │
│   ├── hooks/              # Custom React hooks
│   │   └── use-mobile.tsx  # Mobile detection hook
│   │
│   ├── lib/                # Utility functions
│   │   └── utils.ts        # Helper functions
│   │
│   ├── App.tsx             # Main app component with routing
│   ├── main.tsx            # Application entry point
│   └── index.css           # Global styles
│
├── public/                 # Static assets
├── .env                    # Environment variables
├── vite.config.ts          # Vite configuration
├── tailwind.config.ts      # Tailwind configuration
└── tsconfig.json           # TypeScript configuration
```

---

## 🎯 State Management Architecture

Spacedly uses a **hybrid state management approach** combining Redux Toolkit and RTK Query:

### Redux Toolkit (Application State)

Redux Toolkit is used for global application state that needs to be shared across components.

#### Store Configuration (`store/store.ts`)

```typescript
import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import taskReducer from './slices/taskSlice';
// ... other reducers

export const store = configureStore({
  reducer: {
    // Application state slices
    auth: authReducer,
    task: taskReducer,
    analytics: analyticsReducer,
    ui: uiReducer,
    
    // RTK Query API slices (for caching)
    [authApi.reducerPath]: authApi.reducer,
    [taskApi.reducerPath]: taskApi.reducer,
    // ... other API slices
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(
      authApi.middleware,
      taskApi.middleware,
      // ... other API middlewares
    ),
});
```

**Key Features:**
- ✅ Automatic Redux DevTools integration
- ✅ Built-in Immer for immutable updates
- ✅ Thunk middleware included by default
- ✅ Simplified reducer creation with `createSlice`

### State Slices

#### Auth Slice Example (`slices/authSlice.ts`)

```typescript
import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  accessToken: string | null;
  user: {
    id: string;
    email: string;
    name: string;
  } | null;
}

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setCredentials: (state, action) => {
      // Immer allows "mutating" syntax
      state.accessToken = action.payload.accessToken;
      state.user = action.payload.user;
      state.isAuthenticated = true;
    },
    logout: (state) => {
      state.accessToken = null;
      state.user = null;
      state.isAuthenticated = false;
    },
  },
});
```

**Usage in Components:**
```typescript
import { useAppDispatch, useAppSelector } from '@/store/hooks';
import { setCredentials, logout } from '@/store/slices/authSlice';

function MyComponent() {
  const dispatch = useAppDispatch();
  const { user, isAuthenticated } = useAppSelector(state => state.auth);
  
  const handleLogin = (credentials) => {
    dispatch(setCredentials(credentials));
  };
}
```

### Typed Hooks (`store/hooks.ts`)

```typescript
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';
import type { RootState, AppDispatch } from './store';

// Pre-typed hooks for better TypeScript support
export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;
```

**Why Typed Hooks?**
- ✅ Automatic type inference for state
- ✅ No need to type `state` parameter every time
- ✅ Better autocomplete in IDE

---

## 🔄 API Management with RTK Query

RTK Query is Redux Toolkit's powerful data fetching and caching solution. It eliminates the need to write thunks for API calls.

### How RTK Query Works

```
Component → useGetTasksQuery() → RTK Query Cache → API Call (if needed) → Update Cache → Re-render Component
                                       ↓
                                 Check Cache First
                                       ↓
                              If fresh data exists,
                              return without API call
```

### API Slice Structure (`api/taskApi.ts`)

```typescript
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

export const taskApi = createApi({
  reducerPath: 'taskApi',
  
  // Base query configuration
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include', // Send cookies with requests
  }),
  
  // Cache tag types for invalidation
  tagTypes: ['Task', 'Analytics'],
  
  // Endpoints definition
  endpoints: (builder) => ({
    // Query endpoints (GET requests)
    getTasks: builder.query<{ tasks: Task[] }, void>({
      query: () => '/tasks',
      providesTags: ['Task'], // Tags this data
      transformResponse: (response: any) => {
        // Transform API response before caching
        return {
          tasks: response.data.tasks.map(transformTask),
        };
      },
    }),
    
    getTask: builder.query<Task, string>({
      query: (id) => `/tasks/${id}`,
      providesTags: ['Task'],
    }),
    
    // Mutation endpoints (POST/PUT/DELETE)
    createTask: builder.mutation({
      query: (task) => ({
        url: '/tasks',
        method: 'POST',
        body: task,
      }),
      invalidatesTags: ['Task', 'Analytics'], // Invalidate cache
    }),
    
    updateTask: builder.mutation({
      query: ({ id, ...task }) => ({
        url: `/tasks/${id}`,
        method: 'PUT',
        body: task,
      }),
      invalidatesTags: ['Task'],
    }),
    
    deleteTask: builder.mutation({
      query: (id: string) => ({
        url: `/tasks/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Task', 'Analytics'],
    }),
  }),
});

// Auto-generated hooks
export const {
  useGetTasksQuery,
  useGetTaskQuery,
  useCreateTaskMutation,
  useUpdateTaskMutation,
  useDeleteTaskMutation,
} = taskApi;
```

### Using RTK Query in Components

#### Fetching Data (Queries)

```typescript
import { useGetTasksQuery } from '@/store/api/taskApi';

function TaskList() {
  const {
    data,           // The returned data
    error,          // Error object if request failed
    isLoading,      // True on first load
    isFetching,     // True on any fetch (including refetch)
    isSuccess,      // True if request succeeded
    refetch,        // Manual refetch function
  } = useGetTasksQuery();
  
  if (isLoading) return <Spinner />;
  if (error) return <Error message={error.message} />;
  
  return (
    <div>
      {data.tasks.map(task => (
        <TaskCard key={task.id} task={task} />
      ))}
    </div>
  );
}
```

**Query Features:**
- ✅ Automatic caching
- ✅ Automatic refetching on window focus
- ✅ Automatic refetching on network reconnect
- ✅ Polling support
- ✅ Loading and error states

#### Mutating Data (Mutations)

```typescript
import { useCreateTaskMutation } from '@/store/api/taskApi';

function CreateTaskForm() {
  const [createTask, { isLoading, error }] = useCreateTaskMutation();
  
  const handleSubmit = async (taskData) => {
    try {
      const result = await createTask(taskData).unwrap();
      console.log('Task created:', result);
      // Cache automatically invalidated, list will refetch
    } catch (err) {
      console.error('Failed to create task:', err);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      {/* form fields */}
      <button disabled={isLoading}>
        {isLoading ? 'Creating...' : 'Create Task'}
      </button>
    </form>
  );
}
```

**Mutation Features:**
- ✅ Optimistic updates
- ✅ Automatic cache invalidation
- ✅ Loading states
- ✅ Error handling

### Advanced RTK Query Features

#### Conditional Fetching

```typescript
function TaskDetails({ taskId }: { taskId?: string }) {
  const { data } = useGetTaskQuery(taskId!, {
    skip: !taskId, // Don't fetch if taskId is undefined
  });
}
```

#### Polling

```typescript
function RealTimeTaskList() {
  const { data } = useGetTasksQuery(undefined, {
    pollingInterval: 30000, // Refetch every 30 seconds
  });
}
```

#### Prefetching

```typescript
function TaskListWithPrefetch() {
  const dispatch = useAppDispatch();
  
  const handleMouseEnter = (taskId: string) => {
    // Prefetch task details on hover
    dispatch(taskApi.util.prefetch('getTask', taskId));
  };
}
```

---

## 💾 Caching Strategy

### RTK Query Caching System

RTK Query implements a sophisticated caching mechanism:

```
┌─────────────────────────────────────────────────────────┐
│                    RTK Query Cache                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Cache Entry: 'getTasks(undefined)'                     │
│  ├─ Data: [{ id: 1, title: 'Task 1' }, ...]            │
│  ├─ Status: 'fulfilled'                                 │
│  ├─ Tags: ['Task']                                      │
│  ├─ Subscriptions: [Component1, Component2]             │
│  └─ Last Updated: 2025-12-08T10:00:00Z                 │
│                                                          │
│  Cache Entry: 'getTask("task-123")'                     │
│  ├─ Data: { id: 'task-123', title: 'Specific Task' }   │
│  ├─ Status: 'fulfilled'                                 │
│  ├─ Tags: ['Task']                                      │
│  └─ Last Updated: 2025-12-08T10:05:00Z                 │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Cache Invalidation Flow

```
1. User creates new task
   ↓
2. createTask mutation executes
   ↓
3. Mutation completes successfully
   ↓
4. RTK Query invalidates tags: ['Task', 'Analytics']
   ↓
5. All queries with these tags automatically refetch:
   - getTasks (to show new task)
   - getAnalytics (to update stats)
   ↓
6. Components re-render with fresh data
```

### Tag System

Tags are used to establish relationships between queries and mutations:

```typescript
// This query provides 'Task' tag
getTasks: builder.query({
  query: () => '/tasks',
  providesTags: ['Task'], // "This data is tagged as 'Task'"
}),

// This mutation invalidates 'Task' tag
createTask: builder.mutation({
  query: (task) => ({ url: '/tasks', method: 'POST', body: task }),
  invalidatesTags: ['Task'], // "Refetch all 'Task' queries"
}),
```

### Advanced Tag Patterns

#### Individual Item Tags

```typescript
getTasks: builder.query({
  query: () => '/tasks',
  providesTags: (result) =>
    result
      ? [
          ...result.tasks.map(({ id }) => ({ type: 'Task' as const, id })),
          { type: 'Task', id: 'LIST' },
        ]
      : [{ type: 'Task', id: 'LIST' }],
}),

updateTask: builder.mutation({
  query: ({ id, ...task }) => ({
    url: `/tasks/${id}`,
    method: 'PUT',
    body: task,
  }),
  invalidatesTags: (result, error, { id }) => [{ type: 'Task', id }],
  // Only invalidates this specific task, not the whole list
}),
```

### Cache Behavior

| Scenario | Cache Behavior |
|----------|---------------|
| **First Load** | API call → Cache data → Return data |
| **Component Remount** | Return cached data immediately → Refetch in background if stale |
| **Window Focus** | Refetch if data is stale |
| **Network Reconnect** | Refetch all subscribed queries |
| **Manual Refetch** | Always fetch fresh data |
| **Tag Invalidation** | Remove cached data → Refetch all subscribed queries |

### Cache Timing

```typescript
// Default cache behavior (can be customized per endpoint)
const taskApi = createApi({
  // ...
  keepUnusedDataFor: 60, // Keep cache for 60 seconds after last subscription
  refetchOnMountOrArgChange: 30, // Refetch if data is older than 30 seconds
  refetchOnFocus: true, // Refetch when window regains focus
  refetchOnReconnect: true, // Refetch when network reconnects
});
```

---

## 🔐 Authentication Flow

Spacedly uses **HTTP-only cookies** for secure authentication:

### Authentication Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     Authentication Flow                     │
└────────────────────────────────────────────────────────────┘

1. User Login
   ↓
2. POST /api/auth/login (email, password)
   ↓
3. Backend validates credentials
   ↓
4. Backend sets HTTP-only cookies:
   - accessToken (15 minutes)
   - refreshToken (7 days)
   ↓
5. Frontend receives user data (no tokens in response)
   ↓
6. Redux updates auth state:
   dispatch(setCredentials({ user }))
   ↓
7. Protected routes now accessible

Request with Auth:
   ↓
GET /api/tasks (cookies sent automatically)
   ↓
Backend validates accessToken from cookie
   ↓
Returns data

Token Expiry:
   ↓
Access token expires (401 error)
   ↓
Axios interceptor catches 401
   ↓
POST /api/auth/refresh (sends refreshToken cookie)
   ↓
Backend validates refreshToken
   ↓
Sets new accessToken cookie
   ↓
Retry original request
   ↓
If refresh fails → Redirect to login
```

### Axios Interceptor (`services/axios.ts`)

```typescript
// Response interceptor for automatic token refresh
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If 401 and haven't tried to refresh yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh token
        await axios.post(
          `${API_BASE_URL}/auth/refresh`,
          {},
          { withCredentials: true } // Send refreshToken cookie
        );

        // Retry original request with new accessToken
        return axiosInstance(originalRequest);
      } catch (refreshError) {
        // Refresh failed, redirect to login
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);
```

### Protected Routes

```typescript
// ProtectedRoute component
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAppSelector(state => state.auth);
  
  if (isLoading) return <LoadingScreen />;
  if (!isAuthenticated) return <Navigate to="/login" />;
  
  return <>{children}</>;
}

// Usage in routing
<Route
  path="/dashboard"
  element={
    <ProtectedRoute>
      <Dashboard />
    </ProtectedRoute>
  }
/>
```

### Auth Initialization

```typescript
// On app startup, verify auth status
const initializeAuth = async () => {
  try {
    const response = await axios.get('/auth/me', {
      withCredentials: true,
    });
    dispatch(setCredentials({ user: response.data.user }));
  } catch (error) {
    dispatch(logout());
  }
};
```

---

## 🧩 Component Architecture

### Component Hierarchy

```
App.tsx
├── AppLayout (for authenticated routes)
│   ├── AppSidebar
│   │   ├── Navigation Links
│   │   └── User Profile
│   └── Outlet (route content)
│       ├── Dashboard
│       ├── Tasks
│       ├── Analytics
│       └── Calendar
│
└── Public Routes
    ├── Landing
    ├── Login
    └── Signup
```

### Component Patterns

#### Smart vs Presentational Components

**Smart Component (Container):**
```typescript
// Handles data fetching and state
function TaskListContainer() {
  const { data, isLoading } = useGetTasksQuery();
  const [deleteTask] = useDeleteTaskMutation();
  
  return (
    <TaskList 
      tasks={data?.tasks || []}
      isLoading={isLoading}
      onDelete={deleteTask}
    />
  );
}
```

**Presentational Component:**
```typescript
// Pure UI component
interface TaskListProps {
  tasks: Task[];
  isLoading: boolean;
  onDelete: (id: string) => void;
}

function TaskList({ tasks, isLoading, onDelete }: TaskListProps) {
  if (isLoading) return <Spinner />;
  
  return (
    <div>
      {tasks.map(task => (
        <TaskCard key={task.id} task={task} onDelete={onDelete} />
      ))}
    </div>
  );
}
```

### shadcn/ui Integration

Spacedly uses shadcn/ui, which provides:
- ✅ 40+ pre-built, accessible components
- ✅ Built on Radix UI primitives
- ✅ Fully customizable with Tailwind
- ✅ Copy-paste into your project (no npm package)

**Example: Using Dialog Component**
```typescript
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

function CreateTaskDialog() {
  const [open, setOpen] = useState(false);
  
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>Create Task</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create New Task</DialogTitle>
        </DialogHeader>
        <TaskForm onSubmit={() => setOpen(false)} />
      </DialogContent>
    </Dialog>
  );
}
```

---

## 🗺 Routing & Navigation

### React Router Configuration (`App.tsx`)

```typescript
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        
        {/* Protected Routes */}
        <Route element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/tasks" element={<Tasks />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/calendar" element={<CalendarPage />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/profile" element={<Profile />} />
        </Route>
        
        {/* 404 */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}
```

### Programmatic Navigation

```typescript
import { useNavigate } from 'react-router-dom';

function MyComponent() {
  const navigate = useNavigate();
  
  const handleSuccess = () => {
    navigate('/dashboard');
  };
  
  const goBack = () => {
    navigate(-1);
  };
}
```

---

## ⚙️ Development Workflow

### Environment Setup

1. **Install Dependencies:**
   ```bash
   cd frontend
   yarn install
   ```

2. **Configure Environment Variables:**
   ```bash
   # .env
   VITE_API_URL=http://localhost:5000/api
   ```

3. **Start Development Server:**
   ```bash
   yarn dev
   ```
   Runs on http://localhost:5173

### Build Process

```bash
# Development build
yarn build:dev

# Production build
yarn build

# Preview production build
yarn preview
```

### Vite Configuration

```typescript
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'), // @ = src/
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API calls in development
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
});
```

---

## ✅ Best Practices

### State Management

✅ **Use RTK Query for server state**
- All API data should use RTK Query
- Automatic caching, refetching, and invalidation

✅ **Use Redux slices for client state**
- UI state (modals, theme, etc.)
- User preferences
- Application-wide state

❌ **Don't duplicate server state in Redux slices**
```typescript
// ❌ Bad - duplicating data
const tasksSlice = createSlice({
  name: 'tasks',
  initialState: { tasks: [] },
  reducers: {
    setTasks: (state, action) => {
      state.tasks = action.payload; // This data is already in RTK Query cache!
    },
  },
});

// ✅ Good - let RTK Query handle it
const { data: tasks } = useGetTasksQuery();
```

### Component Design

✅ **Keep components small and focused**
```typescript
// ✅ Good - single responsibility
function TaskTitle({ title }: { title: string }) {
  return <h2>{title}</h2>;
}

function TaskActions({ onEdit, onDelete }: TaskActionsProps) {
  return (
    <div>
      <Button onClick={onEdit}>Edit</Button>
      <Button onClick={onDelete}>Delete</Button>
    </div>
  );
}
```

✅ **Use TypeScript interfaces for props**
```typescript
interface TaskCardProps {
  task: Task;
  onEdit: (task: Task) => void;
  onDelete: (id: string) => void;
}

function TaskCard({ task, onEdit, onDelete }: TaskCardProps) {
  // Implementation
}
```

### Performance

✅ **Memoize expensive computations**
```typescript
import { useMemo } from 'react';

function TaskList({ tasks }: { tasks: Task[] }) {
  const sortedTasks = useMemo(() => {
    return [...tasks].sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }, [tasks]);
  
  return <div>{/* render sortedTasks */}</div>;
}
```

✅ **Use React.memo for pure components**
```typescript
import { memo } from 'react';

const TaskCard = memo(({ task }: { task: Task }) => {
  return <div>{task.title}</div>;
});
```

### Form Handling

✅ **Use React Hook Form + Zod**
```typescript
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const taskSchema = z.object({
  title: z.string().min(1, 'Title is required'),
  description: z.string().optional(),
  priority: z.enum(['low', 'medium', 'high']),
});

function CreateTaskForm() {
  const form = useForm({
    resolver: zodResolver(taskSchema),
    defaultValues: {
      title: '',
      description: '',
      priority: 'medium',
    },
  });
  
  const onSubmit = (data: z.infer<typeof taskSchema>) => {
    // Type-safe data
    console.log(data);
  };
  
  return (
    <form onSubmit={form.handleSubmit(onSubmit)}>
      <input {...form.register('title')} />
      {form.formState.errors.title && (
        <span>{form.formState.errors.title.message}</span>
      )}
    </form>
  );
}
```

### Error Handling

✅ **Handle errors at multiple levels**
```typescript
// RTK Query level
const { data, error, isError } = useGetTasksQuery();

if (isError) {
  return <Alert>Error: {error.message}</Alert>;
}

// Component level
try {
  await createTask(taskData).unwrap();
} catch (err) {
  toast.error('Failed to create task');
}

// Global level (Error Boundary)
class ErrorBoundary extends React.Component {
  componentDidCatch(error, errorInfo) {
    logErrorToService(error, errorInfo);
  }
  
  render() {
    if (this.state.hasError) {
      return <ErrorFallback />;
    }
    return this.props.children;
  }
}
```

---

## 📊 Data Flow Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    Complete Data Flow                        │
└─────────────────────────────────────────────────────────────┘

User Action (Click "Create Task")
   ↓
Component calls mutation hook
   ↓
const [createTask] = useCreateTaskMutation();
await createTask(taskData);
   ↓
RTK Query sends API request
   ↓
POST /api/tasks with credentials (cookies)
   ↓
Backend validates auth token from cookie
   ↓
Backend creates task in database
   ↓
Backend returns created task
   ↓
RTK Query receives response
   ↓
RTK Query invalidates tags: ['Task', 'Analytics']
   ↓
All queries with these tags refetch:
  - getTasks → GET /api/tasks
  - getAnalytics → GET /api/analytics
   ↓
RTK Query updates cache
   ↓
Components automatically re-render with new data
   ↓
User sees updated task list
```

---

## 🎓 Learning Resources

### Official Documentation
- [Redux Toolkit](https://redux-toolkit.js.org/)
- [RTK Query](https://redux-toolkit.js.org/rtk-query/overview)
- [React Router](https://reactrouter.com/)
- [Tailwind CSS](https://tailwindcss.com/)
- [shadcn/ui](https://ui.shadcn.com/)

### Key Concepts to Master
1. **RTK Query Caching** - Understanding when data is fetched vs cached
2. **Tag Invalidation** - How mutations trigger refetches
3. **TypeScript with Redux** - Type-safe state management
4. **React Hook Form** - Performant form handling
5. **Component Composition** - Building reusable UI components

---

## 🐛 Debugging Tips

### Redux DevTools

1. **Install Redux DevTools Extension**
   - Chrome/Firefox extension
   - Automatically works with Redux Toolkit

2. **View State Changes**
   - See every action dispatched
   - Time-travel debugging
   - Inspect state at any point

### RTK Query DevTools

```typescript
// View cache state
store.getState().taskApi; // See all cached queries

// Manually invalidate tags
dispatch(taskApi.util.invalidateTags(['Task']));

// Manually update cache
dispatch(
  taskApi.util.updateQueryData('getTasks', undefined, (draft) => {
    draft.tasks.push(newTask);
  })
);
```

### Network Debugging

```typescript
// Log all API requests
const taskApi = createApi({
  baseQuery: fetchBaseQuery({
    baseUrl: API_BASE_URL,
    credentials: 'include',
    prepareHeaders: (headers) => {
      console.log('API Request Headers:', headers);
      return headers;
    },
  }),
});
```

---

## 🚀 Deployment

### Build for Production

```bash
yarn build
```

Outputs to `dist/` directory.

### Environment Variables for Production

```bash
# .env.production
VITE_API_URL=https://api.spacedly.com/api
```

### Deploy to Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

See `vercel.json` for configuration.

---

## 📝 Summary

Spacedly's frontend is built with modern React patterns:

- ✅ **Type-safe** with TypeScript
- ✅ **Performant** with RTK Query caching
- ✅ **Maintainable** with Redux Toolkit
- ✅ **Accessible** with shadcn/ui
- ✅ **Secure** with HTTP-only cookie authentication
- ✅ **Developer-friendly** with hot reload and DevTools

The architecture prioritizes developer experience while maintaining production-ready performance and security.

---

## 🎤 Interview Questions by Topic

### Redux Toolkit & State Management

#### Q1: What is Redux Toolkit and how does it differ from traditional Redux?
**Answer:**
Redux Toolkit (RTK) is the official, opinionated toolset for efficient Redux development. Key differences:

**Redux Toolkit:**
- ✅ Uses `createSlice` - combines actions and reducers
- ✅ Built-in Immer - allows "mutating" syntax
- ✅ Automatic Redux DevTools integration
- ✅ Includes thunk middleware by default
- ✅ Simplified store configuration

**Traditional Redux:**
- ❌ Requires separate action types, action creators, and reducers
- ❌ Must manually ensure immutability
- ❌ More boilerplate code
- ❌ Manual DevTools setup

**Example Comparison:**
```typescript
// Traditional Redux (verbose)
const SET_USER = 'SET_USER';
const setUser = (user) => ({ type: SET_USER, payload: user });
function authReducer(state = initialState, action) {
  switch (action.type) {
    case SET_USER:
      return { ...state, user: action.payload }; // Manual immutability
    default:
      return state;
  }
}

// Redux Toolkit (concise)
const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setUser: (state, action) => {
      state.user = action.payload; // Immer makes this safe
    },
  },
});
```

#### Q2: Explain the difference between local component state, Redux state, and RTK Query cache state.
**Answer:**

**Local Component State (useState, useReducer):**
- Scoped to single component
- Lost when component unmounts
- Use for: UI state (form inputs, toggles, local flags)
- Example: Modal open/close state

**Redux State (createSlice):**
- Global application state
- Persists across route changes
- Use for: User preferences, theme, app-wide UI state
- Example: Dark mode preference

**RTK Query Cache State:**
- Managed by RTK Query
- Automatically cached and invalidated
- Use for: Server data (API responses)
- Example: Tasks, user data, analytics

**Decision Tree:**
```
Does this data come from an API?
├─ YES → Use RTK Query
└─ NO → Is it needed across components?
    ├─ YES → Use Redux slice
    └─ NO → Use local state
```

#### Q3: What is Immer and how does Redux Toolkit use it?
**Answer:**
Immer is a library that enables "mutating" syntax while maintaining immutability under the hood.

**How it works:**
1. Immer creates a "draft" proxy of your state
2. You "mutate" the draft directly
3. Immer tracks changes and produces a new immutable state

**In Redux Toolkit:**
```typescript
const tasksSlice = createSlice({
  name: 'tasks',
  initialState: { items: [] },
  reducers: {
    addTask: (state, action) => {
      // Looks like mutation, but Immer makes it immutable
      state.items.push(action.payload);
      // Equivalent to: return { ...state, items: [...state.items, action.payload] }
    },
    updateTask: (state, action) => {
      const task = state.items.find(t => t.id === action.payload.id);
      if (task) {
        task.title = action.payload.title; // Direct "mutation"
      }
    },
  },
});
```

**Benefits:**
- ✅ More readable code
- ✅ Less error-prone than spread operators
- ✅ Automatically handles deep updates

---

### RTK Query & API Management

#### Q4: How does RTK Query differ from traditional data fetching approaches?
**Answer:**

**Traditional Approach (Redux Thunks + useState):**
```typescript
function TaskList() {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    setLoading(true);
    fetch('/api/tasks')
      .then(res => res.json())
      .then(data => setTasks(data))
      .catch(err => setError(err))
      .finally(() => setLoading(false));
  }, []);
  
  // Manual refetch, no caching, lots of boilerplate
}
```

**RTK Query Approach:**
```typescript
function TaskList() {
  const { data, error, isLoading } = useGetTasksQuery();
  // Automatic caching, refetching, error handling
}
```

**Key Differences:**
| Feature | Traditional | RTK Query |
|---------|-------------|-----------|
| Boilerplate | High | Minimal |
| Caching | Manual | Automatic |
| Refetching | Manual | Automatic |
| Loading states | Manual | Automatic |
| Error handling | Manual | Built-in |
| Optimistic updates | Complex | Simple |
| Cache invalidation | Manual | Tag-based |

#### Q5: Explain the RTK Query tag system and cache invalidation.
**Answer:**

**Tags** establish relationships between queries and mutations:

```typescript
// Queries "provide" tags
getTasks: builder.query({
  query: () => '/tasks',
  providesTags: ['Task'], // This data is tagged as 'Task'
}),

// Mutations "invalidate" tags
createTask: builder.mutation({
  query: (task) => ({ url: '/tasks', method: 'POST', body: task }),
  invalidatesTags: ['Task'], // Refetch all queries tagged with 'Task'
}),
```

**Cache Invalidation Flow:**
```
1. User creates task → createTask mutation
2. Mutation succeeds
3. RTK Query invalidates 'Task' tag
4. All queries providing 'Task' tag automatically refetch
5. Components re-render with fresh data
```

**Advanced Pattern - Individual Item Tags:**
```typescript
getTasks: builder.query({
  providesTags: (result) =>
    result
      ? [
          ...result.tasks.map(({ id }) => ({ type: 'Task', id })),
          { type: 'Task', id: 'LIST' },
        ]
      : [{ type: 'Task', id: 'LIST' }],
}),

updateTask: builder.mutation({
  invalidatesTags: (result, error, { id }) => [
    { type: 'Task', id }, // Only invalidate this specific task
  ],
}),
```

This invalidates only the updated task, not the entire list.

#### Q6: What is the difference between a query and a mutation in RTK Query?
**Answer:**

**Query:**
- Used for fetching/reading data (GET requests)
- Returns: `{ data, error, isLoading, isFetching, refetch }`
- Automatically caches results
- Refetches on component mount, window focus, network reconnect
- Example: `useGetTasksQuery()`

**Mutation:**
- Used for creating/updating/deleting data (POST/PUT/DELETE)
- Returns: `[trigger, { isLoading, error, data }]`
- Does NOT cache results
- Invalidates cache tags to trigger refetches
- Example: `useCreateTaskMutation()`

**Usage:**
```typescript
// Query - automatic execution
const { data } = useGetTasksQuery(); // Runs immediately

// Mutation - manual trigger
const [createTask, { isLoading }] = useCreateTaskMutation();
const handleSubmit = async (taskData) => {
  await createTask(taskData); // Called manually
};
```

#### Q7: How would you implement optimistic updates with RTK Query?
**Answer:**

Optimistic updates immediately update the UI before the server responds:

```typescript
deleteTask: builder.mutation({
  query: (id: string) => ({
    url: `/tasks/${id}`,
    method: 'DELETE',
  }),
  // Optimistic update
  async onQueryStarted(id, { dispatch, queryFulfilled }) {
    // Optimistically update cache
    const patchResult = dispatch(
      taskApi.util.updateQueryData('getTasks', undefined, (draft) => {
        draft.tasks = draft.tasks.filter(task => task.id !== id);
      })
    );
    
    try {
      await queryFulfilled; // Wait for server confirmation
    } catch {
      patchResult.undo(); // Rollback on error
    }
  },
}),
```

**Benefits:**
- ✅ Instant UI feedback
- ✅ Better perceived performance
- ✅ Automatic rollback on failure

---

### Caching Strategy

#### Q8: How does RTK Query decide when to refetch data?
**Answer:**

RTK Query refetches based on several conditions:

**1. On Component Mount:**
```typescript
const { data } = useGetTasksQuery(undefined, {
  refetchOnMountOrArgChange: 30, // Refetch if data is older than 30 seconds
});
```

**2. On Window Focus:**
```typescript
const taskApi = createApi({
  refetchOnFocus: true, // Refetch when user returns to tab
});
```

**3. On Network Reconnect:**
```typescript
const taskApi = createApi({
  refetchOnReconnect: true, // Refetch when internet reconnects
});
```

**4. On Tag Invalidation:**
```typescript
// When a mutation invalidates tags
invalidatesTags: ['Task']
```

**5. Manual Refetch:**
```typescript
const { refetch } = useGetTasksQuery();
refetch(); // Manual trigger
```

**6. Polling:**
```typescript
const { data } = useGetTasksQuery(undefined, {
  pollingInterval: 30000, // Refetch every 30 seconds
});
```

#### Q9: What strategies can you use to optimize cache performance?
**Answer:**

**1. Use Specific Tags:**
```typescript
// ❌ Bad - invalidates everything
invalidatesTags: ['Task']

// ✅ Good - invalidates specific items
invalidatesTags: (result, error, { id }) => [{ type: 'Task', id }]
```

**2. Configure Cache Timing:**
```typescript
const taskApi = createApi({
  keepUnusedDataFor: 60, // Keep cached data for 60 seconds
});
```

**3. Prefetch Data:**
```typescript
const handleMouseEnter = (taskId: string) => {
  dispatch(taskApi.util.prefetch('getTask', taskId));
};
```

**4. Skip Unnecessary Fetches:**
```typescript
const { data } = useGetTaskQuery(taskId!, {
  skip: !taskId, // Don't fetch if no ID
});
```

**5. Use Selective Invalidation:**
```typescript
// Only invalidate analytics, not task list
invalidatesTags: ['Analytics']
```

---

### Authentication & Security

#### Q10: Why use HTTP-only cookies instead of localStorage for authentication tokens?
**Answer:**

**HTTP-only Cookies:**
- ✅ Not accessible via JavaScript (prevents XSS attacks)
- ✅ Automatically sent with requests
- ✅ Can set secure flag (HTTPS only)
- ✅ Can set SameSite flag (CSRF protection)

**localStorage:**
- ❌ Accessible via JavaScript (vulnerable to XSS)
- ❌ Must manually attach to requests
- ❌ No built-in security features

**Security Comparison:**
```typescript
// ❌ Vulnerable to XSS
localStorage.setItem('token', accessToken);
// Malicious script can: localStorage.getItem('token')

// ✅ Protected
// Token in HTTP-only cookie - JavaScript cannot access it
```

**Implementation:**
```typescript
// Backend sets HTTP-only cookie
res.cookie('accessToken', token, {
  httpOnly: true,  // Not accessible via JS
  secure: true,    // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 15 * 60 * 1000, // 15 minutes
});

// Frontend - cookie sent automatically
const { data } = useGetTasksQuery(); // Cookie included automatically
```

#### Q11: Explain the token refresh flow in detail.
**Answer:**

**Complete Flow:**

```
1. User logs in
   ↓
2. Backend sets two cookies:
   - accessToken (short-lived: 15 min)
   - refreshToken (long-lived: 7 days)
   ↓
3. User makes API request
   ↓
4. Request includes accessToken cookie automatically
   ↓
5. Backend validates accessToken
   ↓
6. [After 15 minutes] AccessToken expires
   ↓
7. API returns 401 Unauthorized
   ↓
8. Axios interceptor catches 401
   ↓
9. POST /auth/refresh (includes refreshToken cookie)
   ↓
10. Backend validates refreshToken
   ↓
11. Backend issues new accessToken cookie
   ↓
12. Retry original request with new accessToken
   ↓
13. If refresh fails → Redirect to login
```

**Implementation:**
```typescript
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        await axios.post('/auth/refresh', {}, { withCredentials: true });
        return axiosInstance(originalRequest); // Retry with new token
      } catch (refreshError) {
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);
```

---

### React Performance

#### Q12: When should you use useMemo vs React.memo?
**Answer:**

**useMemo** - Memoizes a computed value
```typescript
function TaskList({ tasks }: { tasks: Task[] }) {
  // useMemo - expensive computation
  const sortedTasks = useMemo(() => {
    console.log('Sorting tasks...');
    return [...tasks].sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }, [tasks]); // Only recompute when tasks change
  
  return <div>{sortedTasks.map(...)}</div>;
}
```

**React.memo** - Memoizes entire component
```typescript
// Component only re-renders if props change
const TaskCard = React.memo(({ task, onDelete }: TaskCardProps) => {
  console.log('Rendering TaskCard');
  return (
    <div>
      <h3>{task.title}</h3>
      <button onClick={() => onDelete(task.id)}>Delete</button>
    </div>
  );
});

// ⚠️ Be careful with object/function props
function TaskList() {
  // ❌ Bad - creates new function every render
  const handleDelete = (id: string) => console.log(id);
  
  // ✅ Good - memoized function
  const handleDelete = useCallback((id: string) => {
    console.log(id);
  }, []);
  
  return <TaskCard task={task} onDelete={handleDelete} />;
}
```

**When to use:**
- **useMemo**: Expensive calculations (sorting, filtering large arrays)
- **React.memo**: Components that render often with same props

#### Q13: How does RTK Query prevent unnecessary re-renders?
**Answer:**

RTK Query uses several strategies:

**1. Structural Sharing:**
```typescript
// Even if API returns same data, RTK Query detects no changes
const { data } = useGetTasksQuery();
// If tasks haven't changed, same reference is returned
// → No re-render
```

**2. Selective Subscriptions:**
```typescript
// Only subscribes to specific parts of cache
const { data, isLoading } = useGetTasksQuery();
// Component only re-renders when data or isLoading change
// Not when isFetching or other properties change
```

**3. Normalized Cache:**
```typescript
// Updates to individual items don't affect entire list
updateTask: builder.mutation({
  invalidatesTags: (result, error, { id }) => [
    { type: 'Task', id } // Only this task refetches
  ],
});
```

---

### TypeScript

#### Q14: What is the benefit of typed hooks in Redux?
**Answer:**

**Without Typed Hooks:**
```typescript
// ❌ Need to type state every time
const user = useSelector((state: RootState) => state.auth.user);
const dispatch = useDispatch<AppDispatch>();
```

**With Typed Hooks:**
```typescript
// hooks.ts
export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;

// In components
const user = useAppSelector(state => state.auth.user); // Auto-typed!
const dispatch = useAppDispatch(); // Auto-typed!
```

**Benefits:**
- ✅ Automatic type inference
- ✅ Better autocomplete
- ✅ Less boilerplate
- ✅ Catch errors at compile time

#### Q15: How do you ensure type safety with RTK Query?
**Answer:**

**1. Type Endpoint Responses:**
```typescript
interface Task {
  id: string;
  title: string;
  status: 'pending' | 'completed';
}

getTasks: builder.query<{ tasks: Task[] }, void>({
  //                      ↑ Response type  ↑ Argument type
  query: () => '/tasks',
}),
```

**2. Type Mutation Arguments:**
```typescript
createTask: builder.mutation<
  Task,                                    // Response
  Omit<Task, 'id' | 'createdAt'>          // Argument
>({
  query: (task) => ({
    url: '/tasks',
    method: 'POST',
    body: task, // Fully typed
  }),
}),
```

**3. Transform Responses:**
```typescript
getTasks: builder.query<{ tasks: Task[] }, void>({
  query: () => '/tasks',
  transformResponse: (response: ApiResponse<Task[]>) => {
    // Type-safe transformation
    return {
      tasks: response.data.tasks.map(transformTask),
    };
  },
}),
```

---

### Component Architecture

#### Q16: Explain the difference between Smart and Presentational components.
**Answer:**

**Smart (Container) Components:**
- Handle data fetching and business logic
- Connect to Redux/RTK Query
- Manage state
- Pass data and callbacks to presentational components

```typescript
function TaskListContainer() {
  const { data, isLoading } = useGetTasksQuery();
  const [deleteTask] = useDeleteTaskMutation();
  const [filter, setFilter] = useState('all');
  
  const filteredTasks = useMemo(() => {
    if (!data) return [];
    return data.tasks.filter(task => 
      filter === 'all' || task.status === filter
    );
  }, [data, filter]);
  
  return (
    <TaskList 
      tasks={filteredTasks}
      isLoading={isLoading}
      onDelete={deleteTask}
      filter={filter}
      onFilterChange={setFilter}
    />
  );
}
```

**Presentational Components:**
- Pure UI components
- Receive data via props
- No direct data fetching
- Highly reusable

```typescript
interface TaskListProps {
  tasks: Task[];
  isLoading: boolean;
  onDelete: (id: string) => void;
  filter: string;
  onFilterChange: (filter: string) => void;
}

function TaskList({ tasks, isLoading, onDelete, filter, onFilterChange }: TaskListProps) {
  if (isLoading) return <Spinner />;
  
  return (
    <div>
      <FilterBar value={filter} onChange={onFilterChange} />
      {tasks.map(task => (
        <TaskCard key={task.id} task={task} onDelete={onDelete} />
      ))}
    </div>
  );
}
```

**Benefits:**
- ✅ Separation of concerns
- ✅ Easier testing (presentational components)
- ✅ Better reusability
- ✅ Clearer component hierarchy

#### Q17: When should you create a custom hook?
**Answer:**

Create custom hooks when you have:

**1. Reusable Logic:**
```typescript
// ✅ Good - reusable data fetching logic
function useTask(taskId: string) {
  const { data, isLoading } = useGetTaskQuery(taskId, {
    skip: !taskId,
  });
  
  const task = data?.task;
  
  return {
    task,
    isLoading,
    isEmpty: !isLoading && !task,
  };
}

// Usage in multiple components
function TaskDetails({ taskId }: { taskId: string }) {
  const { task, isLoading, isEmpty } = useTask(taskId);
}
```

**2. Complex State Logic:**
```typescript
function useTaskFilters() {
  const [filters, setFilters] = useState({
    status: 'all',
    priority: 'all',
    search: '',
  });
  
  const updateFilter = useCallback((key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  }, []);
  
  const resetFilters = useCallback(() => {
    setFilters({ status: 'all', priority: 'all', search: '' });
  }, []);
  
  return {
    filters,
    updateFilter,
    resetFilters,
  };
}
```

**3. Side Effect Management:**
```typescript
function useDocumentTitle(title: string) {
  useEffect(() => {
    document.title = `${title} | Spacedly`;
    return () => {
      document.title = 'Spacedly';
    };
  }, [title]);
}
```

---

### Form Handling

#### Q18: Why use React Hook Form instead of controlled inputs?
**Answer:**

**Controlled Inputs (useState):**
```typescript
// ❌ Re-renders on every keystroke
function Form() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  return (
    <form>
      <input 
        value={email} 
        onChange={(e) => setEmail(e.target.value)} // Re-render
      />
      <input 
        value={password} 
        onChange={(e) => setPassword(e.target.value)} // Re-render
      />
    </form>
  );
}
```

**React Hook Form (Uncontrolled):**
```typescript
// ✅ Minimal re-renders
function Form() {
  const { register, handleSubmit } = useForm();
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('email')} /> {/* No re-render */}
      <input {...register('password')} /> {/* No re-render */}
    </form>
  );
}
```

**Performance Comparison:**
| Approach | Re-renders | Bundle Size | Validation |
|----------|-----------|-------------|------------|
| useState | Every keystroke | Small | Manual |
| React Hook Form | On submit/blur | Small | Built-in + Zod |
| Formik | Every keystroke | Large | Built-in |

**Benefits of React Hook Form:**
- ✅ Better performance (fewer re-renders)
- ✅ Built-in validation
- ✅ Works with Zod for type-safe schemas
- ✅ Less boilerplate

---

### System Design

#### Q19: How would you implement real-time features in this architecture?
**Answer:**

**Option 1: Polling with RTK Query**
```typescript
const { data } = useGetNotificationsQuery(undefined, {
  pollingInterval: 5000, // Poll every 5 seconds
});
```

**Option 2: WebSockets + RTK Query Cache Updates**
```typescript
useEffect(() => {
  const socket = io('wss://api.spacedly.com');
  
  socket.on('taskCreated', (task: Task) => {
    // Update RTK Query cache
    dispatch(
      taskApi.util.updateQueryData('getTasks', undefined, (draft) => {
        draft.tasks.unshift(task);
      })
    );
  });
  
  return () => socket.disconnect();
}, [dispatch]);
```

**Option 3: Server-Sent Events (SSE)**
```typescript
useEffect(() => {
  const eventSource = new EventSource('/api/notifications/stream');
  
  eventSource.onmessage = (event) => {
    const notification = JSON.parse(event.data);
    dispatch(addNotification(notification));
  };
  
  return () => eventSource.close();
}, [dispatch]);
```

#### Q20: How would you handle pagination with RTK Query?
**Answer:**

**Implementation:**
```typescript
getTasks: builder.query<
  { tasks: Task[]; total: number; page: number },
  { page: number; limit: number }
>({
  query: ({ page, limit }) => `/tasks?page=${page}&limit=${limit}`,
  providesTags: (result) =>
    result
      ? [
          ...result.tasks.map(({ id }) => ({ type: 'Task' as const, id })),
          { type: 'Task', id: 'PARTIAL-LIST' },
        ]
      : [{ type: 'Task', id: 'PARTIAL-LIST' }],
  // Merge pages for infinite scroll
  serializeQueryArgs: ({ endpointName }) => {
    return endpointName;
  },
  merge: (currentCache, newItems, { arg }) => {
    if (arg.page === 1) {
      return newItems; // First page - replace
    }
    return {
      ...newItems,
      tasks: [...currentCache.tasks, ...newItems.tasks], // Append
    };
  },
  forceRefetch({ currentArg, previousArg }) {
    return currentArg !== previousArg;
  },
}),
```

**Usage:**
```typescript
function InfiniteTaskList() {
  const [page, setPage] = useState(1);
  const { data, isFetching } = useGetTasksQuery({ page, limit: 20 });
  
  const loadMore = () => setPage(prev => prev + 1);
  
  return (
    <div>
      {data?.tasks.map(task => <TaskCard key={task.id} task={task} />)}
      <button onClick={loadMore} disabled={isFetching}>
        Load More
      </button>
    </div>
  );
}
```

---

These interview questions cover the core concepts and real-world scenarios you'll encounter when working with Spacedly's frontend architecture.
