import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { initializeAuth } from "./store/initializeAuth";

// Initialize authentication state on app load
initializeAuth();

createRoot(document.getElementById("root")!).render(<App />);
