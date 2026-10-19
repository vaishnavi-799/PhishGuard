import React from 'react'; import ReactDOM from 'react-dom/client'; import {BrowserRouter} from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css'; import 'bootstrap/dist/js/bootstrap.bundle.min.js'; import './styles/theme.css';
import App from './App.jsx';import {AuthProvider} from './auth/AuthContext.jsx'; import {ToastProvider} from './components/ui.jsx';
ReactDOM.createRoot(document.getElementById('root')).render(<BrowserRouter><AuthProvider><ToastProvider><App/></ToastProvider></AuthProvider></BrowserRouter>);
