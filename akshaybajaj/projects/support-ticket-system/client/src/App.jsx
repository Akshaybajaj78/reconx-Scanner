import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import Navbar from "./components/Navbar";
import ProtectedRoute from "./components/ProtectedRoute";

import Login from "./pages/Login";
import Register from "./pages/Register";

import ClientDashboard from "./pages/client/ClientDashboard";
import CreateTicket from "./pages/client/CreateTicket";
import TicketDetails from "./pages/client/TicketDetails";

import AgentDashboard from "./pages/agent/AgentDashboard";
import AgentTicketDetails from "./pages/agent/AgentTicketDetails";

import { useAuth } from "./context/AuthContext";

function App() {
  const { user } = useAuth();

  return (
    <BrowserRouter>
      <Navbar />

      <Routes>
        <Route
          path="/"
          element={
            <Navigate
              to={
                user
                  ? user.role === "agent"
                    ? "/agent"
                    : "/dashboard"
                  : "/login"
              }
            />
          }
        />

        <Route path="/login" element={<Login />} />

        <Route
          path="/register"
          element={<Register />}
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute role="client">
              <ClientDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/create-ticket"
          element={
            <ProtectedRoute role="client">
              <CreateTicket />
            </ProtectedRoute>
          }
        />

        <Route
          path="/ticket/:id"
          element={
            <ProtectedRoute role="client">
              <TicketDetails />
            </ProtectedRoute>
          }
        />

        <Route
          path="/agent"
          element={
            <ProtectedRoute role="agent">
              <AgentDashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/agent/ticket/:id"
          element={
            <ProtectedRoute role="agent">
              <AgentTicketDetails />
            </ProtectedRoute>
          }
        />

        <Route
          path="*"
          element={<Navigate to="/" />}
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;