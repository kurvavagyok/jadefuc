import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import ScanListPage from "./pages/ScanListPage";
import ScanDetailPage from "./pages/ScanDetailPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";

const App = () => {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/scans" element={<ScanListPage />} />
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
      <Route path="*" element={<Navigate to="/dashboard" />} />
    </Routes>
  );
};

export default App;