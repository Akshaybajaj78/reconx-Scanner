import React, { StrictMode, Component } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const rootEl = document.getElementById("root");
if (rootEl) {
  rootEl.innerHTML =
    '<div style="padding:24px;color:#e8f1ff;font-family:monospace;position:relative;z-index:9999">Loading ReconX UI...</div>';
}

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    // Keep this visible in browser console for fast debugging.
    console.error("React render error:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "24px", color: "#fff", fontFamily: "monospace" }}>
          <h2>UI render failed</h2>
          <p>{String(this.state.error)}</p>
        </div>
      );
    }
    return this.props.children;
  }
}

try {
  createRoot(rootEl).render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>
  );
} catch (error) {
  rootEl.innerHTML = `<div style="padding:24px;color:#fff;font-family:monospace;position:relative;z-index:9999"><h2>Boot failed</h2><p>${String(
    error
  )}</p></div>`;
  console.error("React boot error:", error);
}
