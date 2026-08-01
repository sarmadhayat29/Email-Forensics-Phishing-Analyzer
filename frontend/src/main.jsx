import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter } from 'react-router-dom'
import App from './App.jsx'
import './index.css'

// HashRouter keeps client routes in the URL fragment (#/dashboard).
// A browser refresh always requests "/" (or index.html) from the server, so
// deep links never 404 on Vite, FastAPI, Live Server, or static hosts.
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>,
)
