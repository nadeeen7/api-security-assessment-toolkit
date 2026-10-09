import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import AssessmentPage from "./pages/AssessmentPage";
import ProgressPage from "./pages/ProgressPage";
import ResultsPage from "./pages/ResultsPage";
import FindingsPage from "./pages/FindingsPage";
import ReportsPage from "./pages/ReportsPage";
import HistoryPage from "./pages/HistoryPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<AssessmentPage />} />
        <Route path="assessment/:jobId" element={<ProgressPage />} />
        <Route path="assessment/:jobId/results" element={<ResultsPage />} />
        <Route path="assessment/:jobId/findings" element={<FindingsPage />} />
        <Route
          path="assessment/:jobId/findings/:index"
          element={<FindingsPage />}
        />
        <Route path="assessment/:jobId/reports" element={<ReportsPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
