# Spacedly - Smart Spaced Revision Reminder App

A production-ready frontend application for spaced revision learning with intelligent reminders, built with React, TypeScript, Redux Toolkit, and Tailwind CSS.

## 🚀 Features

- **Authentication**: Email/password login and Google OAuth integration
- **Task Management**: Create, update, and delete learning tasks with categories and priorities
- **Spaced Reminders**: Multiple reminders per task with intelligent scheduling
- **Visual Calendar**: View and manage reminders with FullCalendar integration
- **Analytics Dashboard**: Track progress with charts, streaks, and insights
- **Notifications**: Real-time in-app notifications
- **Dark/Light Mode**: Beautiful themes with smooth transitions
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile
- **PWA Support**: Install as a native app

## 🛠️ Tech Stack

- **Frontend Framework**: React 18 + TypeScript
- **Build Tool**: Vite
- **State Management**: Redux Toolkit + RTK Query
- **Styling**: Tailwind CSS
- **Routing**: React Router v6
- **HTTP Client**: Axios
- **Charts**: Recharts
- **Calendar**: FullCalendar
- **Icons**: Lucide React
- **Animations**: Framer Motion
- **UI Components**: shadcn/ui

## 📋 Prerequisites

- Node.js 18+ and npm
- Backend API (see API Configuration below)

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd spacedly
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Edit `.env` and set your backend API URL:

```env
VITE_API_BASE_URL=http://localhost:3000/api
```

### 4. Start Development Server

```bash
npm run dev
```

The app will be available at `http://localhost:8080`

## 🏗️ Project Structure

```
src/
├── components/          # Reusable components
│   ├── ui/             # shadcn/ui components
│   ├── AppSidebar.tsx  # Main navigation sidebar
│   ├── StatCard.tsx    # Statistics card component
│   └── ...
├── config/             # Configuration files
│   └── api.ts          # API endpoints configuration
├── layouts/            # Layout components
│   └── AppLayout.tsx   # Main app layout with sidebar
├── pages/              # Page components
│   ├── Landing.tsx     # Landing page
│   ├── Login.tsx       # Login page
│   ├── Signup.tsx      # Signup page
│   ├── Dashboard.tsx   # Main dashboard
│   ├── Tasks.tsx       # Task management
│   ├── CalendarPage.tsx # Calendar view
│   ├── Analytics.tsx   # Analytics and insights
│   └── ...
├── services/           # API services
│   └── axios.ts        # Axios instance with interceptors
├── store/              # Redux store
│   ├── api/           # RTK Query APIs
│   ├── slices/        # Redux slices
│   ├── store.ts       # Store configuration
│   └── hooks.ts       # Typed Redux hooks
├── App.tsx             # Main app component with routing
└── main.tsx            # Application entry point
```

## 🔐 Authentication Flow

1. **Email/Password Login**: Users can log in with email and password
2. **Google OAuth**: Click "Continue with Google" button redirects to backend OAuth flow
3. **Token Management**: Access and refresh tokens stored in HTTP-only cookies
4. **Auto-refresh**: Axios interceptor automatically refreshes expired tokens
5. **Protected Routes**: Unauthorized users are redirected to login

## 🎨 Design System

The app uses a comprehensive design system defined in `src/index.css` and `tailwind.config.ts`:

- **Colors**: Semantic color tokens (primary, success, warning, destructive)
- **Gradients**: Custom gradient utilities
- **Shadows**: Glow and elevation shadows
- **Animations**: Smooth transitions and micro-interactions
- **Typography**: Inter font family with proper hierarchy

## 📡 API Integration

### Backend Requirements

The app expects the following API endpoints:

#### Authentication
- `POST /auth/login` - Email/password login
- `POST /auth/register` - User registration
- `POST /auth/logout` - Logout
- `POST /auth/refresh` - Refresh access token
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset password
- `GET /auth/google` - Initiate Google OAuth

#### Tasks
- `GET /tasks` - Get all tasks
- `GET /tasks/:id` - Get task by ID
- `POST /tasks` - Create task
- `PUT /tasks/:id` - Update task
- `DELETE /tasks/:id` - Delete task

#### Reminders
- `GET /reminders` - Get all reminders
- `GET /tasks/:taskId/reminders` - Get task reminders
- `POST /reminders` - Create reminder
- `PUT /reminders/:id` - Update reminder
- `DELETE /reminders/:id` - Delete reminder

#### Analytics
- `GET /analytics` - Get analytics data
- `GET /analytics/streaks` - Get streak information

#### Notifications
- `GET /notifications` - Get all notifications
- `PATCH /notifications/:id/read` - Mark as read

## 🚀 Build for Production

```bash
npm run build
```

The production build will be in the `dist/` directory.

## 🧪 Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Lint code with ESLint

### Code Style

- Use TypeScript for type safety
- Follow React best practices and hooks patterns
- Use Redux Toolkit for state management
- Prefer RTK Query for API calls
- Use Tailwind CSS utility classes
- Follow the design system tokens

## 🎯 Key Features Implementation

### Redux Store Structure

- **authSlice**: Authentication state
- **userSlice**: User profile data
- **taskSlice**: Tasks management
- **reminderSlice**: Reminders data
- **analyticsSlice**: Analytics data
- **notificationSlice**: Notifications
- **uiSlice**: UI state (theme, sidebar)

### RTK Query APIs

- **authApi**: Authentication endpoints
- **taskApi**: Task CRUD operations
- **reminderApi**: Reminder CRUD operations
- **analyticsApi**: Analytics data
- **notificationApi**: Notification operations

## 🌐 Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## 📧 Support

For support, email support@spacedly.com or open an issue on GitHub.

---

Built with ❤️ by the Spacedly Team
