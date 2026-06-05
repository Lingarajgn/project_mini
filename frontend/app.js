const API_BASE = 'http://127.0.0.1:8000';

function setMessage(el, text, isError = false) {
    el.textContent = text;
    el.style.color = isError ? '#ff7a90' : '#a78bfa';
}

function getToken() {
    return localStorage.getItem('token');
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = 'login.html';
}

function authHeaders() {
    return {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${getToken()}`,
    };
}

function requireAuth() {
    if (!getToken()) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

async function registerUser(e) {
    e.preventDefault();
    const message = document.getElementById('registerMessage');
    try {
        const res = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                fullname: document.getElementById('fullname').value,
                email: document.getElementById('email').value,
                password: document.getElementById('password').value,
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Registration failed');
        setMessage(message, 'Registration successful. You can now sign in.', false);
    } catch (err) {
        setMessage(message, err.message, true);
    }
}

async function loginUser(e) {
    e.preventDefault();
    const message = document.getElementById('loginMessage');
    try {
        const res = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: document.getElementById('loginEmail').value,
                password: document.getElementById('loginPassword').value,
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Login failed');
        localStorage.setItem('token', data.access_token);
        setMessage(message, 'Login successful. Redirecting…', false);
        setTimeout(() => (window.location.href = 'dashboard.html'), 500);
    } catch (err) {
        setMessage(message, err.message, true);
    }
}

async function loadDashboard() {
    if (!requireAuth()) return;
    try {
        const res = await fetch(`${API_BASE}/dashboard`, { headers: authHeaders() });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to load dashboard');
        document.getElementById('totalTasks').textContent = data.total_tasks;
        document.getElementById('completedTasks').textContent = data.completed_tasks;
        document.getElementById('pendingTasks').textContent = data.pending_tasks;
        document.getElementById('completionRate').textContent = `${data.completion_rate}%`;
        document.getElementById('totalRoutines').textContent = data.total_routines;
        document.getElementById('focusMessage').textContent = `${data.completed_tasks} tasks completed out of ${data.total_tasks}.`;
    } catch (err) {
        document.getElementById('focusMessage').textContent = err.message;
    }
}

async function loadTasks() {
    if (!requireAuth()) return;
    const list = document.getElementById('taskList');
    const msg = document.getElementById('taskMessage');
    try {
        const res = await fetch(`${API_BASE}/tasks`, { headers: authHeaders() });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to load tasks');
        if (!data.length) {
            list.innerHTML = '<p class="muted">No tasks yet.</p>';
            return;
        }
        list.innerHTML = data
            .map(
                (task) => `
          <article class="task-item">
            <div>
              <strong>${task.title}</strong>
              <div class="task-meta">${task.description || 'No description'} · Priority: ${task.priority} · Status: ${task.status}</div>
              <div class="task-meta">Due: ${task.due_date ? new Date(task.due_date).toLocaleDateString() : 'No due date'}</div>
            </div>
            <span class="badge">${task.status}</span>
          </article>
        `
            )
            .join('');
    } catch (err) {
        setMessage(msg, err.message, true);
    }
}

async function createTask(e) {
    e.preventDefault();
    const msg = document.getElementById('taskMessage');
    try {
        const res = await fetch(`${API_BASE}/tasks`, {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
                title: document.getElementById('taskTitle').value,
                description: document.getElementById('taskDescription').value,
                priority: document.getElementById('taskPriority').value,
                status: document.getElementById('taskStatus').value,
                due_date: document.getElementById('taskDueDate').value || null,
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Task creation failed');
        setMessage(msg, 'Task created successfully.', false);
        document.getElementById('taskForm').reset();
        loadTasks();
    } catch (err) {
        setMessage(msg, err.message, true);
    }
}

function bindButtons() {
    document.querySelectorAll('#logoutBtn').forEach((btn) => btn.addEventListener('click', logout));
    const registerForm = document.getElementById('registerForm');
    if (registerForm) registerForm.addEventListener('submit', registerUser);
    const loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', loginUser);
    const taskForm = document.getElementById('taskForm');
    if (taskForm) taskForm.addEventListener('submit', createTask);
}

window.addEventListener('DOMContentLoaded', () => {
    bindButtons();
    if (document.getElementById('dashboardStats')) loadDashboard();
    if (document.getElementById('taskList')) loadTasks();
});
